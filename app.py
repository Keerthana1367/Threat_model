# ========================
# 📦 Library Imports
# ========================
import openai
import gradio as gr
from pymongo import MongoClient
from datetime import datetime
import re
import csv
import os
import pandas as pd
from collections import defaultdict, deque
from dotenv import load_dotenv

# ========================
# 🔐 Load .env Variables (optional for local testing)
# ========================
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
MONGODB_URI = os.getenv("MONGODB_URI", "")

openai.api_key = OPENAI_API_KEY
client_ai = openai

mongo_client = MongoClient(MONGODB_URI)
db = mongo_client["threat_db"]
attack_tree_collection = db["attack_trees"]
prompt_library = db["prompt_library"]

EXPORT_DIR = "csv_exports"
os.makedirs(EXPORT_DIR, exist_ok=True)

# ========================
# 🔧 Utility Functions
# ========================
def parse_mermaid_to_named_edges(mermaid_code):
    node_labels = {}
    edges = []
    lines = mermaid_code.splitlines()
    for line in lines:
        node_match = re.findall(r'(\w+)\[(.+?)\]', line)
        for node_id, label in node_match:
            node_labels[node_id.strip()] = label.strip()
    edge_pattern = re.compile(r'(\w+)\s*-->\s*(\w+)')
    for line in lines:
        match = edge_pattern.search(line)
        if match:
            parent_id = match.group(1).strip()
            child_id = match.group(2).strip()
            parent_label = node_labels.get(parent_id, parent_id)
            child_label = node_labels.get(child_id, child_id)
            edges.append((parent_label, child_label))
    return edges

def build_ordered_paths(edges):
    tree = defaultdict(list)
    indegree = defaultdict(int)
    for parent, child in edges:
        tree[parent].append(child)
        indegree[child] += 1
    roots = set(tree.keys()) - set(indegree.keys())
    if not roots:
        return []
    root = list(roots)[0]
    paths = []
    queue = deque([(root, [root])])
    while queue:
        node, path = queue.popleft()
        if node not in tree:
            paths.append(path)
        else:
            for child in tree[node]:
                queue.append((child, path + [child]))
    return paths

def export_structured_csv(label, paths):
    safe_label = label[:30].replace(' ', '_').replace('/', '_')
    filename = f"{safe_label}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(EXPORT_DIR, filename)
    with open(filepath, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Surface Goal", "Attack Vector", "Technique", "Method", "Path"])
        for path in paths:
            row = path[:4] + [" > ".join(path)]
            while len(row) < 5:
                row.insert(len(row) - 1, "")
            writer.writerow(row)
    return filepath

def read_csv_as_dataframe(filepath):
    try:
        df = pd.read_csv(filepath)
        df.drop_duplicates(subset=["Path"], inplace=True)
        return df
    except Exception:
        return pd.DataFrame(columns=["Surface Goal", "Attack Vector", "Technique", "Method", "Path"])

# ========================
# 📌 Tab 1: Generate from Label
# ========================
def generate_attack_tree_from_label(label_selected):
    if not label_selected:
        return "❌ Select a threat scenario."
    doc = prompt_library.find_one({"label": label_selected}) or prompt_library.find_one({"aliases": {"$in": [label_selected.lower()]}})
    if not doc or "prompt" not in doc:
        return f"❌ No prompt or alias found for '{label_selected}'"
    matched_prompt = doc["prompt"]
    label_to_save = doc["label"]
    try:
        system_message = {
            "role": "system",
            "content": "You are a cybersecurity expert. Return only the attack tree in Mermaid format using:\n```mermaid\ngraph TD\n...```"
        }
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[system_message, {"role": "user", "content": matched_prompt}],
            temperature=0.3,
            max_tokens=1500
        )
        raw = response.choices[0].message.content.strip()
        match = re.search(r"```mermaid\s*(graph TD[\s\S]*?)```", raw)
        if not match:
            return "❌ Mermaid diagram not found or invalid format."
        mermaid_code = match.group(1).strip()
        attack_tree_collection.update_one(
            {"label": label_to_save},
            {"$set": {
                "prompt": matched_prompt,
                "mermaid_code": mermaid_code,
                "updated_at": datetime.utcnow()
            }},
            upsert=True
        )
        return f"```mermaid\n{mermaid_code}\n```"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# ========================
# 📜 Tab 2: View Stored Trees
# ========================
def wrapper_load(label):
    if not label:
        return "❌ Select a saved attack tree.", pd.DataFrame(), None
    doc = attack_tree_collection.find_one({"label": label}) or prompt_library.find_one({"aliases": {"$in": [label.lower()]}})
    if doc and "label" in doc and "mermaid_code" not in doc:
        return generate_attack_tree_from_label(doc["label"]), pd.DataFrame(), None
    if not doc or "mermaid_code" not in doc:
        return "❌ No stored attack tree found.", pd.DataFrame(), None
    mermaid_code = doc["mermaid_code"]
    edges = parse_mermaid_to_named_edges(mermaid_code)
    paths = build_ordered_paths(edges)
    csv_path = export_structured_csv(doc["label"], paths)
    df = read_csv_as_dataframe(csv_path)
    return f"```mermaid\n{mermaid_code}\n```", df, csv_path

# ========================
# 📾 Tab 3: Free Prompt
# ========================
def generate_tree_from_free_prompt(prompt):
    if not prompt.strip():
        return "❌ Please enter a valid prompt"
    try:
        all_docs = list(prompt_library.find({}, {"label": 1, "aliases": 1, "prompt": 1, "_id": 0}))
        matched_doc = None
        for doc in all_docs:
            if "label" not in doc:
                continue
            label = doc["label"].lower()
            aliases = [a.lower() for a in doc.get("aliases", [])]
            if label in prompt.lower() or any(alias in prompt.lower() for alias in aliases):
                matched_doc = doc
                break

        if matched_doc:
            base_prompt = matched_doc["prompt"]
            label_to_save = matched_doc["label"]
            extended_prompt = f"{base_prompt}\n\n# Extension:\n{prompt}"
            system_msg = {
                "role": "system",
                "content": "You are a cybersecurity expert. Return the full updated attack tree in Mermaid format:\n```mermaid\ngraph TD\n...```"
            }
            response = client_ai.chat.completions.create(
                model="gpt-4-turbo",
                messages=[system_msg, {"role": "user", "content": extended_prompt}],
                temperature=0.3,
                max_tokens=1200
            )
            raw = response.choices[0].message.content.strip()
            match = re.search(r"```mermaid\s*(graph TD[\s\S]*?)```", raw)
            if not match:
                return "❌ Mermaid diagram not found or invalid format."
            mermaid_code = match.group(1).strip()
            attack_tree_collection.update_one(
                {"label": label_to_save},
                {"$set": {"prompt": extended_prompt, "mermaid_code": mermaid_code, "updated_at": datetime.utcnow()}},
                upsert=True
            )
            prompt_library.update_one(
                {"label": label_to_save},
                {"$set": {"prompt": extended_prompt, "updated_at": datetime.utcnow()}},
                upsert=True
            )
            return f"```mermaid\n{mermaid_code}\n```"

        label_resp = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Generate a short, descriptive lowercase label (2–4 words) for this cybersecurity attack surface or scenario."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=12,
            temperature=0.3
        )
        new_label = label_resp.choices[0].message.content.strip().lower().replace(" ", "_")

        alias_resp = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Give 3–5 short aliases or alternative names for the following cybersecurity concept or attack surface. Return only a Python list."},
                {"role": "user", "content": new_label.replace("_", " ")}
            ],
            max_tokens=100,
            temperature=0.5
        )
        try:
            alias_text = alias_resp.choices[0].message.content.strip()
            alias_list = eval(alias_text) if alias_text.startswith("[") else [new_label]
            alias_list = [a.lower().strip() for a in alias_list if a.strip()]
            if new_label not in alias_list:
                alias_list.append(new_label)
        except:
            alias_list = [new_label]

        tree_resp = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Generate a full attack tree for the following prompt in Mermaid format starting with:\n```mermaid\ngraph TD"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1500
        )
        raw_tree = tree_resp.choices[0].message.content.strip()
        match = re.search(r"```mermaid\s*(graph TD[\s\S]*?)```", raw_tree)
        if not match:
            return "❌ Mermaid diagram not found or invalid format."
        mermaid_code = match.group(1).strip()

        prompt_library.insert_one({
            "label": new_label,
            "aliases": alias_list,
            "prompt": prompt,
            "created_at": datetime.utcnow()
        })
        attack_tree_collection.insert_one({
            "label": new_label,
            "prompt": prompt,
            "mermaid_code": mermaid_code,
            "created_at": datetime.utcnow()
        })

        return f"```mermaid\n{mermaid_code}\n```"

    except Exception as e:
        return f"❌ Error: {str(e)}"

# ========================
# 🚀 Dropdown Refresher
# ========================
def get_all_labels():
    return sorted([doc["label"] for doc in prompt_library.find({}, {"label": 1})])

def get_stored_labels():
    return sorted(set([doc["label"] for doc in attack_tree_collection.find({"label": {"$exists": True}})]))

def refresh_dropdowns():
    return gr.update(choices=get_all_labels()), gr.update(choices=get_stored_labels())

# ========================
# 🎨 Gradio UI
# ========================
with gr.Blocks() as demo:
    with gr.Tab("🧠 Generate Attack Tree"):
        gr.Markdown("### 🔐 attack tree")
        label_dropdown = gr.Dropdown(choices=[], label="📌 Select or Type", interactive=True, allow_custom_value=True)
        generate_button = gr.Button("🚀 Generate Attack Tree")
        mermaid_display = gr.Markdown(label="📈 Generated Attack Tree")
        generate_button.click(fn=generate_attack_tree_from_label, inputs=label_dropdown, outputs=mermaid_display)

    with gr.Tab("📂 Library"):
        gr.Markdown("### 📉 View and Export Structured Threat Trees")
        saved_dropdown = gr.Dropdown(choices=[], label="📌 Select Stored Tree", interactive=True, allow_custom_value=True)
        mermaid_output = gr.Markdown(label="📈 Saved Attack Tree")
        relation_table = gr.Dataframe(headers=["Surface Goal", "Attack Vector", "Technique", "Method", "Path"], datatype=["str"]*5, interactive=False)
        download_button = gr.File(label="📅 Download CSV")
        regen_button = gr.Button("🔄 Regenerate Tree from Prompt")
        saved_dropdown.change(fn=wrapper_load, inputs=saved_dropdown, outputs=[mermaid_output, relation_table, download_button])
        regen_button.click(fn=generate_attack_tree_from_label, inputs=saved_dropdown, outputs=mermaid_output)

    with gr.Tab("🗓️ Custom Prompt"):
        gr.Markdown("🔍 Explore and Extend Threat Trees")
        prompt_input = gr.Textbox(label="Enter your Custom Prompt", lines=5, placeholder="e.g. Add another attack vector to CAN Bus")
        custom_mermaid_output = gr.Markdown(label="📌 Extended Attack Tree")
        submit_button = gr.Button("Generate and Update Tree")
        submit_button.click(fn=generate_tree_from_free_prompt, inputs=prompt_input, outputs=custom_mermaid_output).then(
            fn=refresh_dropdowns, inputs=[], outputs=[label_dropdown, saved_dropdown]
        )

    demo.load(fn=refresh_dropdowns, inputs=[], outputs=[label_dropdown, saved_dropdown])

# ========================
# 🌐 Render-compatible Launch
# ========================
if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=int(os.environ.get("PORT", 8080)))
