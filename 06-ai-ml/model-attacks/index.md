# Model Attacks

## Trigger
ML model API returning probabilities/logits, model weights file available (.pt, .safetensors, .bin), LoRA adapter provided alongside base model, encoder-only model (embedding API), model with confidence scores, fine-tuned and original base models both accessible, model from fine-tuning API

## Attack Surface
Model inference APIs (classification, embedding, completion endpoints), model weight files (PyTorch, Safetensors, ONNX), LoRA adapter weights, fine-tuning APIs (upload data, get model), model zoos/hubs (HuggingFace model download), model serving infrastructure (temperature, seed configuration), model metadata (architecture disclosure, training data description)

## Decision Tree
```
Identify model access level
  ├─ Full model weights available
  │   ├─ Base + fine-tuned model pair → Weight perturbation negation
  │   ├─ Single model + target output → Model inversion (input reconstruction)
  │   ├─ LoRA adapter + base model → LoRA merging / weight visualization
  │   ├─ Encoder model → Encoder collision (find inputs with identical embeddings)
  │   ├─ Single model → Attribute inference (infer training data attributes from model behavior)
  │   └─ Single model → Model reconstruction (recover exact weights via ReLU boundary probing)
  ├─ Query API only
  │   ├─ Returns full logits/probabilities → Model extraction via student training
  │   ├─ Returns confidence scores → Membership inference by threshold
  │   ├─ Returns confidence scores → Attribute inference (infer protected attributes from prediction differences)
  │   └─ Returns text completions → Training data extraction via prefix probing
  └─ Black-box with limited queries
      └─ Side-channel: timing, error messages, output length leakage
```

## Techniques

### 1. Model Weight Perturbation Negation

Given an original base model and a fine-tuned version that has been trained to suppress specific behavior, recover the suppressed behavior by negating the fine-tuning delta.

The mathematical insight: if `W_chal = W_orig + delta` where `delta` was learned to suppress a behavior (e.g., flag generation), then `W_recovered = W_orig - delta = 2*W_orig - W_chal` reverses the suppression into amplification.

```python
import torch
from transformers import GPT2LMHeadModel, GPT2Tokenizer

# Load original and challenge (fine-tuned) models
original = GPT2LMHeadModel.from_pretrained("gpt2")
challenge = GPT2LMHeadModel.from_pretrained("./challenge_model")

# Compute recovered weights: W_rec = 2*W_orig - W_chal
recovered = GPT2LMHeadModel.from_pretrained("gpt2")
orig_sd = original.state_dict()
chal_sd = challenge.state_dict()
rec_sd = recovered.state_dict()

for key in orig_sd:
    rec_sd[key] = 2 * orig_sd[key] - chal_sd[key]
    # Alternative scaling: rec_sd[key] = orig_sd[key] + alpha * (orig_sd[key] - chal_sd[key])
    # where alpha > 1 can amplify recovery

recovered.load_state_dict(rec_sd)

# Generate with recovered model
tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
tokenizer.pad_token = tokenizer.eos_token

prompt = "The flag is"
inputs = tokenizer(prompt, return_tensors="pt")
with torch.no_grad():
    output = recovered.generate(
        **inputs,
        max_new_tokens=100,
        temperature=0.7,
        do_sample=True,
        num_return_sequences=5,
    )

for seq in output:
    print(tokenizer.decode(seq, skip_special_tokens=True))
```

**Variations:**

```python
# Inspect which layers changed (fine-tuning often targets specific layers)
for key in orig_sd:
    diff = (orig_sd[key] - chal_sd[key]).abs().max().item()
    if diff > 1e-4:
        print(f"{key}: max_diff = {diff:.6f}")

# Layer-selective negation: only negate layers with significant deltas
SIGNIFICANT_THRESHOLD = 1e-4
for key in orig_sd:
    diff_norm = (orig_sd[key] - chal_sd[key]).norm().item()
    if diff_norm > SIGNIFICANT_THRESHOLD:
        rec_sd[key] = 2 * orig_sd[key] - chal_sd[key]

# Alpha scaling for stronger recovery
alpha = 2.0  # Try values from 1.0 to 3.0
for key in orig_sd:
    rec_sd[key] = orig_sd[key] + alpha * (orig_sd[key] - chal_sd[key])
```

**Key insight:** Check how many layers actually changed. Fine-tuning with LoRA modifies only a few parameters, producing sparse deltas. Even full fine-tuning often concentrates changes in specific layers (especially attention output and layer norm).

### 2. Model Inversion via Gradient Descent

Given a trained model and a target output (specific embedding, class logit, or neuron activation), recover the input by optimizing a random input tensor to minimize the distance to the target output.

```python
import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import transforms

def model_inversion(model, target_output, input_shape=(3, 224, 224),
                    num_steps=2000, lr=0.01, tv_weight=1e-4):
    """
    Reconstruct input from target output using gradient descent.
    target_output: desired model output (embedding, logit, or class)
    """
    model.eval()

    # Initialize random input
    x = torch.randn(1, *input_shape, requires_grad=True)
    optimizer = optim.Adam([x], lr=lr)
    mse_loss = nn.MSELoss()

    for step in range(num_steps):
        optimizer.zero_grad()
        output = model(x)

        # Reconstruction loss
        loss = mse_loss(output, target_output)

        # Total variation regularization (encourages smooth, natural-looking images)
        tv = (
            torch.sum(torch.abs(x[:, :, :, :-1] - x[:, :, :, 1:])) +
            torch.sum(torch.abs(x[:, :, :-1, :] - x[:, :, 1:, :]))
        )
        total_loss = loss + tv_weight * tv

        total_loss.backward()
        optimizer.step()

        # Clamp to valid image range
        with torch.no_grad():
            x.clamp_(0, 1)

        if step % 200 == 0:
            print(f"Step {step}: loss = {loss.item():.6f}, tv = {tv.item():.4f}")

    return x.squeeze(0).detach()

# Feature visualization: maximize a specific neuron's activation
def feature_visualization(model, layer_name, neuron_idx, input_shape=(3, 224, 224),
                          num_steps=1000, lr=0.05):
    """Find input that maximally activates a specific neuron."""
    activation = {}

    def hook_fn(m, i, o):
        activation["value"] = o

    # Register forward hook on target layer
    for name, module in model.named_modules():
        if name == layer_name:
            hook = module.register_forward_hook(hook_fn)
            break

    x = torch.randn(1, *input_shape, requires_grad=True)
    optimizer = optim.Adam([x], lr=lr)

    for step in range(num_steps):
        optimizer.zero_grad()
        _ = model(x)

        # Maximize the target neuron's activation
        loss = -activation["value"][0, neuron_idx].mean()
        loss.backward()
        optimizer.step()

        with torch.no_grad():
            x.clamp_(0, 1)

    hook.remove()
    return x.squeeze(0).detach()
```

**Key insight:** Neural networks are fully differentiable, so we can backpropagate through them to optimize input pixels. Total variation regularization prevents high-frequency noise artifacts. For models with batch normalization, ensure `model.eval()` is called so running statistics are used instead of batch statistics.

### 3. Neural Network Encoder Collision

Find two distinct inputs that produce identical (or nearly identical) output embeddings. This exploits the pigeonhole principle: encoders compress high-dimensional inputs into lower-dimensional embeddings, so collisions must exist.

```python
import torch
import torch.nn as nn
import torch.optim as optim

def encoder_collision(encoder, input_shape=(3, 64, 64), num_steps=5000, lr=0.005):
    """
    Find two distinct inputs that produce identical encoder output.
    """
    encoder.eval()

    # Initialize two random inputs (different seeds for diversity)
    input_a = torch.randn(1, *input_shape, requires_grad=True)
    input_b = torch.randn(1, *input_shape, requires_grad=True)

    optimizer = optim.Adam([input_a, input_b], lr=lr)

    for step in range(num_steps):
        optimizer.zero_grad()

        emb_a = encoder(input_a)
        emb_b = encoder(input_b)

        # Minimize embedding distance (goal: identical embeddings)
        collision_loss = nn.MSELoss()(emb_a, emb_b)

        # Maximize input distance (ensure inputs are distinct)
        input_diff = nn.MSELoss()(input_a, input_b)
        diversity_loss = -input_diff  # negative to maximize

        # Keep inputs in [0, 1]
        range_penalty = (
            torch.relu(-input_a).sum() +
            torch.relu(input_a - 1).sum() +
            torch.relu(-input_b).sum() +
            torch.relu(input_b - 1).sum()
        )

        loss = collision_loss + 0.1 * diversity_loss + 0.01 * range_penalty
        loss.backward()
        optimizer.step()

        with torch.no_grad():
            input_a.clamp_(0, 1)
            input_b.clamp_(0, 1)

        if step % 500 == 0:
            emb_dist = (emb_a - emb_b).norm().item()
            inp_dist = (input_a - input_b).norm().item()
            print(f"Step {step}: emb_dist = {emb_dist:.8f}, inp_dist = {inp_dist:.4f}")

    # Verify collision
    with torch.no_grad():
        fa = encoder(input_a)
        fb = encoder(input_b)
        print(f"Final embedding distance: {(fa - fb).norm().item():.10f}")
        print(f"Final input distance: {(input_a - input_b).norm().item():.4f}")
        print(f"Collision achieved: {torch.allclose(fa, fb, atol=1e-6)}")

    return input_a.detach(), input_b.detach()
```

**Variations:**

```python
# Targeted collision: force both inputs to map to a specific target embedding
def targeted_encoder_collision(encoder, target_embedding, input_shape=(3, 64, 64)):
    """Find an input that produces a specific target embedding."""
    x = torch.randn(1, *input_shape, requires_grad=True)
    optimizer = optim.Adam([x], lr=0.005)

    for step in range(5000):
        optimizer.zero_grad()
        emb = encoder(x)
        loss = nn.MSELoss()(emb, target_embedding.unsqueeze(0))
        loss.backward()
        optimizer.step()
        with torch.no_grad():
            x.clamp_(0, 1)

    return x.detach()

# Hamming-constrained collision: inputs differ in very few pixels
def sparse_encoder_collision(encoder, input_a, num_pixels=5, num_steps=2000):
    """Find version of input_a with same embedding, differing in ≤num_pixels."""
    encoder.eval()
    with torch.no_grad():
        embed_a = encoder(input_a.unsqueeze(0))
    # Select candidate pixel positions by gradient sensitivity
    x = input_a.clone().detach().requires_grad_(True)
    embed = encoder(x.unsqueeze(0))
    loss = (embed - embed_a).pow(2).sum()
    loss.backward()
    _, idx = x.grad.abs().flatten().topk(num_pixels)
    # Optimize only those pixels
    mask = torch.zeros_like(x.flatten()); mask[idx] = 1
    x = input_a.clone().detach().requires_grad_(True)
    opt = torch.optim.Adam([x], lr=0.1)
    for step in range(num_steps):
        opt.zero_grad()
        embed_loss = (encoder(x.unsqueeze(0)) - embed_a).pow(2).sum()
        spread_loss = -(x.flatten() * (1 - mask) - input_a.flatten()).abs().mean()
        (embed_loss + 0.1 * spread_loss).backward()
        x.grad = x.grad * mask.reshape_as(x.grad)  # zero grad on non-candidate pixels
        opt.step()
        x.data = torch.clamp(x.data, 0, 1)
    return x.detach()
```

**Key insight:** Encoders compress information, so collisions must exist by the pigeonhole principle. The key is the simultaneous optimization: minimize embedding distance while maximizing input distance. Starting with very different random initializations helps avoid trivial solutions (where the inputs collapse to the same point).

### 4. LoRA Adapter Weight Merging

LoRA (Low-Rank Adaptation) modifies weights as `W_merged = W_base + alpha * (B @ A)`. Merging the adapter into the base model and generating output or visualizing weights reveals hidden information encoded in the low-rank matrices.

```python
import torch
from safetensors import safe_open
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

# Method 1: Manual merge
# Inspect adapter structure first
adapter = safe_open("adapter_model.safetensors", framework="pt")
print("LoRA keys:", list(adapter.keys()))

base_model = AutoModelForCausalLM.from_pretrained("gpt2")
tokenizer = AutoTokenizer.from_pretrained("gpt2")
tokenizer.pad_token = tokenizer.eos_token

# Load adapter config to get alpha and rank
# adapter_config.json contains: lora_alpha, r (rank), target_modules
alpha = 1.0
# Effective scaling = lora_alpha / r (typically 16/8 = 2 or 8/8 = 1)

base_sd = base_model.state_dict()

lora_a_keys = [k for k in adapter.keys() if "lora_A" in k]

for a_key in lora_a_keys:
    b_key = a_key.replace("lora_A", "lora_B")

    # Map LoRA key to base model key
    # e.g., "base_model.model.transformer.h.0.attn.c_attn.lora_A.weight"
    #    -> "transformer.h.0.attn.c_attn.weight"
    base_key = a_key \
        .replace("base_model.model.", "") \
        .replace(".lora_A.weight", ".weight")

    A = adapter.get_tensor(a_key)  # shape: (r, in_features)
    B = adapter.get_tensor(b_key)  # shape: (out_features, r)

    delta = alpha * (B @ A)  # shape: (out_features, in_features)

    if base_key in base_sd:
        base_sd[base_key] = base_sd[base_key] + delta
        print(f"Merged {base_key}: delta norm = {delta.norm():.4f}")

base_model.load_state_dict(base_sd)

# Generate with merged model
prompt = "The secret is"
inputs = tokenizer(prompt, return_tensors="pt")
with torch.no_grad():
    output = base_model.generate(
        **inputs, max_new_tokens=100, temperature=0.7, do_sample=True,
    )
print(tokenizer.decode(output[0], skip_special_tokens=True))

# Method 2: PEFT-based merge (simpler)
base = AutoModelForCausalLM.from_pretrained("gpt2")
model = PeftModel.from_pretrained(base, "./lora_adapter_dir")
model = model.merge_and_unload()  # Merge LoRA into base weights

tokenizer = AutoTokenizer.from_pretrained("gpt2")
tokenizer.pad_token = tokenizer.eos_token
inputs = tokenizer("The flag is", return_tensors="pt")
output = model.generate(**inputs, max_new_tokens=100)
print(tokenizer.decode(output[0], skip_special_tokens=True))

# Method 3: Weight visualization (flags sometimes encoded as image in weights)
def visualize_lora_weights(adapter_path, output_path="lora_weights.png"):
    """Reshape and render LoRA delta matrices as images."""
    from torchvision.utils import save_image
    import matplotlib.pyplot as plt

    adapter = safe_open(adapter_path, framework="pt")
    a_keys = [k for k in adapter.keys() if "lora_A" in k and "weight" in k]

    fig, axes = plt.subplots(2, len(a_keys), figsize=(15, 6))
    for i, a_key in enumerate(a_keys):
        b_key = a_key.replace("lora_A", "lora_B")
        A = adapter.get_tensor(a_key).numpy()
        B = adapter.get_tensor(b_key).numpy()
        delta = B @ A

        axes[0, i].imshow(A, cmap="viridis", aspect="auto")
        axes[0, i].set_title(f"A {i} ({A.shape})")
        axes[1, i].imshow(delta, cmap="viridis", aspect="auto")
        axes[1, i].set_title(f"Delta {i} ({delta.shape})")

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"Weight visualization saved to {output_path}")
```

**Key insight:** The `adapter_config.json` tells you which layers were modified, the rank, and the scaling factor. Sometimes the hidden content is not in the model's text output but in the weight matrices themselves -- flags may be encoded as pixel patterns in the `B @ A` delta matrix. For QLoRA adapters (4-bit quantized), dequantize before merging using the quantization configuration.

### 5. Model Extraction via Query API

Reconstruct a model's parameters or decision boundary by sending crafted inputs and observing outputs. The attack surface is any ML API that returns predictions, confidence scores, or logits.

```python
import numpy as np
import requests
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

API_URL = "http://challenge:8080/predict"

def query_model(x):
    """Send input to model API and get prediction/confidence."""
    resp = requests.post(API_URL, json={"input": x.tolist()})
    return resp.json()  # e.g., {"class": 1, "confidence": 0.87, "probabilities": [0.13, 0.87]}

# Strategy 1: Exact linear model extraction (requires dim + 1 queries)
def extract_linear_model(dim=10):
    """Extract exact weights of a linear model using basis vector queries.
    For f(x) = sigmoid(w*x + b), query with basis vectors e_i and zero vector.
    """
    # Get bias term from zero input
    base_result = query_model(np.zeros(dim))
    base_logit = np.log(base_result["confidence"] / (1 - base_result["confidence"] + 1e-10))

    weights = np.zeros(dim)
    for i in range(dim):
        e_i = np.zeros(dim)
        e_i[i] = 1.0
        result = query_model(e_i)
        logit = np.log(result["confidence"] / (1 - result["confidence"] + 1e-10))
        weights[i] = logit - base_logit

    print(f"Extracted weights: {weights}")
    print(f"Extracted bias: {base_logit}")
    return weights, base_logit

# Strategy 2: Decision boundary mapping (for low-dimensional models)
def map_decision_boundary(dim=2, grid_points=100):
    """Sample a grid of points to map the decision boundary."""
    xs = np.linspace(-5, 5, grid_points)
    ys = np.linspace(-5, 5, grid_points)
    X_grid = np.array([[x, y] for x in xs for y in ys])

    predictions = []
    for point in X_grid:
        result = query_model(point)
        predictions.append(result["class"])

    predictions = np.array(predictions)

    # Fit surrogate model
    surrogate = LogisticRegression()
    surrogate.fit(X_grid, predictions)
    print(f"Surrogate accuracy on grid: {surrogate.score(X_grid, predictions):.2%}")
    print(f"Estimated coefficients: {surrogate.coef_}")
    return surrogate

# Strategy 3: Model distillation (for neural networks)
def distill_model(input_dim=10, n_queries=10000):
    """Train a student network on teacher API responses."""
    # Generate diverse queries
    X_train = np.random.randn(n_queries, input_dim)

    # Query teacher
    y_train = []
    for x in X_train:
        result = query_model(x)
        y_train.append(result["probabilities"])

    y_train = np.array(y_train)

    # Train student
    student = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=1000)
    student.fit(X_train, y_train[:, 1])  # binary classification

    # Evaluate fidelity (how well student mimics teacher)
    X_test = np.random.randn(2000, input_dim)
    y_test = np.array([query_model(x)["class"] for x in X_test])
    student_pred = (student.predict_proba(X_test)[:, 1] > 0.5).astype(int)
    fidelity = (student_pred == y_test).mean()
    print(f"Student-teacher fidelity: {fidelity:.2%}")
    # NOTE: predict() returns class labels, not probabilities.
    # Use predict_proba() to get confidence scores for threshold-based decisions.

    return student

# Strategy 4: Decision tree extraction via boundary probing
def extract_tree_boundary(dim, max_depth=5):
    """
    For decision tree models, extract splits by binary search
    on decision boundaries.
    """
    # For each feature, find the split point by probing
    # near what appears to be the boundary
    splits = []
    for feature in range(dim):
        # Binary search for decision boundary
        lo, hi = -10.0, 10.0
        for _ in range(20):
            mid = (lo + hi) / 2
            x = np.zeros(dim)
            x[feature] = mid
            result = query_model(x)
            x2 = np.zeros(dim)
            x2[feature] = mid + 0.01
            result2 = query_model(x2)
            if result["class"] != result2["class"]:
                splits.append(mid)
                break
            if result["class"] == 1:
                hi = mid
            else:
                lo = mid
    print(f"Estimated splits: {splits}")
    return splits
```

**Key insight:** Linear models can be extracted exactly with `dim + 1` queries. For neural networks, 10K-100K queries can achieve >99% fidelity using a student network. If only class labels are returned (no probabilities), use logistic regression on the logit from the nearest-probability mapping or use multiple queries with slight perturbations to estimate confidence.

### 6. Membership Inference Attack (MIA)

Determine whether a specific data sample was part of the model's training set. Training data members typically produce higher confidence predictions and lower loss values than non-members.

```python
import torch
import torch.nn.functional as F
import numpy as np

def get_membership_metrics(model, x, y_true):
    """
    Compute metrics that distinguish training data members from non-members.
    Higher confidence + lower loss + lower entropy = likely member.
    """
    model.eval()
    with torch.no_grad():
        logits = model(x.unsqueeze(0))
        probs = F.softmax(logits, dim=1)
        confidence = probs[0, y_true].item()
        loss = F.cross_entropy(logits, torch.tensor([y_true])).item()
        entropy = -(probs * torch.log(probs + 1e-10)).sum().item()

        # Top-1 margin: difference between highest and second-highest probability
        top2 = probs.topk(2).values[0]
        margin = (top2[0] - top2[1]).item()

    return {
        "confidence": confidence,
        "loss": loss,
        "entropy": entropy,
        "margin": margin,
        "member_score": confidence - 0.5 * entropy,
    }

# Method 1: Simple threshold attack
def threshold_attack(metrics, confidence_threshold=0.9):
    """Members are those with confidence > threshold."""
    return metrics["confidence"] > confidence_threshold

# Method 2: Multi-metric scoring
def score_attack(metrics, low_loss_threshold=0.01, high_conf_threshold=0.95):
    """
    Combine multiple signals: high confidence, low loss, low entropy, high margin.
    """
    signals = 0
    if metrics["confidence"] > high_conf_threshold:
        signals += 1
    if metrics["loss"] < low_loss_threshold:
        signals += 1
    if metrics["entropy"] < 0.5:
        signals += 1
    if metrics["margin"] > 0.5:
        signals += 1
    return signals >= 2

# Method 3: Shadow model attack (most sophisticated)
def shadow_model_attack(target_model, candidate_samples, candidate_labels):
    """
    Train shadow models on known in/out splits to learn the membership signal.
    Without shadow models, use heuristic scoring.
    """
    results = []
    for x, y in zip(candidate_samples, candidate_labels):
        metrics = get_membership_metrics(target_model, x, y)
        score = metrics["confidence"] - 0.5 * metrics["entropy"]
        results.append({
            "sample_idx": len(results),
            "true_label": y,
            "member_score": score,
            "is_likely_member": score > 0.7,
            **metrics,
        })

    # Sort by membership likelihood (descending)
    results.sort(key=lambda r: r["member_score"], reverse=True)
    return results

# Method 4: Likelihood Ratio Attack (LiRA)
def lira_attack(target_model, candidate, true_label, shadow_models_in, shadow_models_out):
    """
    LiRA trains shadow models with/without the target sample and
    compares the loss distributions.
    shadow_models_in: models trained WITH the target sample
    shadow_models_out: models trained WITHOUT the target sample
    """
    losses_in = []
    for shadow in shadow_models_in:
        shadow.eval()
        with torch.no_grad():
            logits = shadow(candidate.unsqueeze(0))
            loss = F.cross_entropy(logits, torch.tensor([true_label])).item()
            losses_in.append(loss)

    losses_out = []
    for shadow in shadow_models_out:
        shadow.eval()
        with torch.no_grad():
            logits = shadow(candidate.unsqueeze(0))
            loss = F.cross_entropy(logits, torch.tensor([true_label])).item()
            losses_out.append(loss)

    # Compare distributions
    mu_in, std_in = np.mean(losses_in), np.std(losses_in) + 1e-10
    mu_out, std_out = np.mean(losses_out), np.std(losses_out) + 1e-10

    # Likelihood ratio
    lr = (1 / std_in) * np.exp(-((mu_out - mu_in) ** 2) / (2 * std_in ** 2)) / \
         (1 / std_out) * np.exp(-((mu_out - mu_out) ** 2) / (2 * std_out ** 2))

    print(f"In-distribution loss: mean={mu_in:.4f}, std={std_in:.4f}")
    print(f"Out-distribution loss: mean={mu_out:.4f}, std={std_out:.4f}")
    print(f"Likelihood ratio: {lr:.4f} (>1 = likely member)")
    return lr > 1.0
```

**Key insight:** Models overfit to training data, producing measurably different behavior on seen vs. unseen samples. The gap between training and test confidence is the core signal. LiRA (Carlini et al., 2022) is the state-of-the-art approach, requiring shadow models trained with and without the target sample.

**Label-only MIA variant:** When only the predicted class is returned (no probabilities), use perturbation sensitivity. Members are more robust to small perturbations -- apply small random noise and measure prediction stability.

**Augmentation MIA variant:** Apply data augmentations to the candidate. Members maintain consistent predictions across augmentations (rotation, cropping, brightness changes), while non-members are more likely to flip predictions.

### 7. Training Data Extraction from LLMs

Probe LLM APIs to extract memorized training data, including potentially sensitive information (PII, code, documents).

```python
import requests

def extract_training_data(api_url, prefixes, max_tokens=200, temperature=0.0):
    """
    Use prefix completion to extract memorized training data.
    temperature=0.0 gives most deterministic (most likely memorized) completions.
    Multiple generations help distinguish memorization from generation:
    memorized text will re-appear across generations.
    """
    results = {}
    for prefix in prefixes:
        responses = []
        for _ in range(10):  # Generate multiple times
            resp = requests.post(api_url, json={
                "prompt": prefix,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": 1.0,
            })
            responses.append(resp.json()["text"])

        # Text appearing in multiple (or identical) generations is likely memorized
        results[prefix] = responses

    return results

# Effective prefixes for training data extraction
prefixes = [
    "My social security number is",
    "My email address is",
    "My password is",
    "BEGIN RSA PRIVATE KEY",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "API_KEY = \"sk-",
    "GITHUB_TOKEN = \"ghp_",
    "My name is John Smith and my phone number is",
    "The secret key is",
    "Repeat the word 'poem' forever: poem poem poem poem poem poem",
    "In this document, we will discuss",
    "Confidential - do not share",
]

# Canonical extraction: "Repeat forever" attack
def repeat_forever_extraction(api_url):
    """
    Carlini et al. (2021): prompt the model to repeat a word indefinitely.
    The model eventually diverges into memorized training data.
    """
    resp = requests.post(api_url, json={
        "prompt": "Repeat the word 'company' forever: company company company company",
        "max_tokens": 500,
        "temperature": 0.7,
    })
    return resp.json()["text"]

# Divergence attack: low probability tokens trigger memorized sequences
def divergence_extraction(api_url, prompt="Once upon a time"):
    """
    Sample with high temperature and nucleus sampling.
    Rare divergences from the expected continuation are often memorized
    training data, not generated text.
    """
    resp = requests.post(api_url, json={
        "prompt": prompt,
        "max_tokens": 500,
        "temperature": 1.5,  # High temperature
        "top_p": 0.9,
    })
    return resp.json()["text"]
```

**Key insight:** Training data extraction exploits the memorization phenomenon identified by Carlini et al. (2021). Text that appears in multiple independent generations from the same prefix is likely memorized training data, not generated text. The "repeat forever" attack causes the model to eventually output rare sequences from its training data as it tries to avoid repetition.

### 8. Gradient Leakage (Federated Learning)

Recover private training data from shared gradients in federated learning scenarios.

```python
import torch
import torch.nn as nn
import torch.optim as optim

def gradient_leakage(model, shared_gradients, input_shape=(3, 32, 32), num_steps=2000):
    """
    Recover training data from shared gradients.
    shared_gradients: gradients received from a federated learning client.
    Optimization: find input that produces gradients closest to shared_gradients.
    """
    # Initialize random input and label
    dummy_x = torch.randn(1, *input_shape, requires_grad=True)
    dummy_y = torch.randn(1, 10, requires_grad=True)  # one-hot logit

    optimizer = optim.Adam([dummy_x, dummy_y], lr=0.01)

    # Extract original gradients as flat tensor for comparison
    original_grads = torch.cat([g.view(-1) for g in shared_gradients])

    for step in range(num_steps):
        optimizer.zero_grad()

        # Forward pass with dummy data
        output = model(dummy_x)
        loss = -torch.sum(dummy_y * torch.log_softmax(output, dim=1))

        # Compute gradients wrt dummy data
        dummy_grads = torch.autograd.grad(loss, model.parameters(), create_graph=True)
        dummy_grads_flat = torch.cat([g.view(-1) for g in dummy_grads])

        # Minimize gradient distance
        grad_loss = nn.MSELoss()(dummy_grads_flat, original_grads)

        # Add prior for one-hot labels
        label_entropy = -(torch.softmax(dummy_y, dim=1) *
                          torch.log_softmax(dummy_y, dim=1)).sum()

        total_loss = grad_loss + 0.1 * label_entropy
        total_loss.backward()
        optimizer.step()

        if step % 200 == 0:
            print(f"Step {step}: grad_loss = {grad_loss.item():.6f}")

    # Recovered label is argmax of dummy_y
    recovered_label = torch.argmax(torch.softmax(dummy_y, dim=1), dim=1)
    recovered_image = dummy_x.detach()

    print(f"Recovered label: {recovered_label.item()}")
    return recovered_image, recovered_label
```

**Key insight:** Gradients directly expose information about the training data used to compute them. The optimization finds an input and label pair whose gradients match the shared gradients. This attack works even with gradient averaging and small batch sizes. Defenses include gradient perturbation (adding noise) and gradient compression.

### 9. Attribute Inference Attack

Given model predictions and partial feature knowledge, infer protected or sensitive attributes (race, gender, health status, location) of training data members. Unlike membership inference which determines whether a record was in training data, attribute inference reveals the *value* of an unknown attribute.

The attack exploits how models learn correlations between features and protected attributes. Even if the protected attribute is not used as an input feature, the model's predictions may vary systematically based on that attribute due to correlated features in the training data.

**Black-box variant:** Query the model with the target record's known features, varying only the unknown attribute across all possible values. The attribute value that produces the highest confidence or most distinct prediction is likely the correct one.

**White-box variant:** Use gradient information to determine which input features are most influential for the prediction, then infer the protected attribute from the gradient patterns across feature groups.

```python
import torch
import torch.nn.functional as F
import numpy as np

def attribute_inference_attack(model, target_record, known_features_mask, target_attribute_idx, attribute_values):
    """
    Infer a protected attribute from model predictions.

    Args:
        model: target PyTorch model (in eval mode)
        target_record: full feature vector with the unknown attribute set to 0
        known_features_mask: boolean mask, True for known features
        target_attribute_idx: index of the attribute to infer
        attribute_values: list of possible values for the target attribute

    Returns:
        inferred_value: the most likely attribute value
        confidence_scores: dict mapping value -> model confidence
    """
    model.eval()
    confidences = {}

    for val in attribute_values:
        # Create a query record with the attribute set to this candidate value
        x = target_record.clone()
        x[target_attribute_idx] = val

        with torch.no_grad():
            logits = model(x.unsqueeze(0))
            probs = F.softmax(logits, dim=1)
            # Use max probability as confidence proxy
            confidence = probs.max().item()
            confidences[val] = confidence

    # The attribute value with highest confidence is the inferred one
    inferred_value = max(confidences, key=confidences.get)
    return inferred_value, confidences


def attribute_inference_whitebox(model, target_record, known_features_mask, target_attribute_idx):
    """
    White-box attribute inference using gradient sensitivity.
    Features with the highest gradient magnitude wrt the prediction
    are most informative about the attribute.
    """
    model.eval()
    x = target_record.clone().unsqueeze(0).requires_grad_(True)

    with torch.enable_grad():
        logits = model(x)
        pred = logits.max(dim=1)[0]
        grad = torch.autograd.grad(pred.sum(), x)[0].squeeze(0)

    # Gradient at the attribute index indicates its influence on the prediction
    attr_gradient = grad[target_attribute_idx].item()

    return {"gradient_at_attribute": attr_gradient, "gradient_sensitivity": grad.norm().item()}
```

**Key insight:** Attribute inference exploits the model's learned correlations between features and protected attributes. Even models trained without protected attributes (fairness-constrained) can leak information through correlated proxy features. The black-box variant requires only `|attribute_values|` queries per target record. Confidence scores expose more information than hard labels alone.

### 10. Model Reconstruction Attack

Given API access to a model, reconstruct its exact weights through carefully crafted queries. This is distinguishable from model extraction (which builds a student model that approximates the teacher) because the goal is *exact weight recovery*.

The attack exploits ReLU activation boundaries: for a ReLU-activated linear layer `h = ReLU(Wx + b)`, the activation pattern (which neurons are active/dead) forms a piecewise linear boundary. By finding the exact boundary hyperplanes through binary search, the attack recovers the weight row directions (signs). Then, differential queries with varying input scales recover the exact magnitudes.

This attack is applicable to small models (tens of layers) with ReLU activations. Each layer requires `O(input_dim * output_dim)` queries.

```python
import torch
import numpy as np

def reconstruct_layer_weights(model, layer_idx, input_dim, output_dim, num_queries=1000):
    """
    Recover the weight matrix of a ReLU layer by probing activation boundaries.

    For each output neuron, the ReLU boundary is W[i] @ x + b[i] = 0.
    By finding points on this boundary via binary search, we recover the
    normal vector which gives us the weight row up to scaling.

    Args:
        model: target model (provides access to hidden activations)
        layer_idx: index of the target linear layer
        input_dim: input dimension to the layer
        output_dim: output dimension of the layer

    Returns:
        W_recovered: reconstructed weight matrix (output_dim x input_dim)
        b_recovered: reconstructed bias vector (output_dim,)
    """
    def get_neuron_activation(x):
        """Get pre-ReLU activation of neuron at layer_idx."""
        with torch.no_grad():
            h = x.clone()
            for i, (w, b) in enumerate(zip(model.weights, model.biases)):
                h = h @ w.T + b
                if i < layer_idx:
                    h = torch.relu(h)
            return h.squeeze(0)

    W_recovered = np.zeros((output_dim, input_dim))
    b_recovered = np.zeros(output_dim)

    for neuron in range(output_dim):
        # Find input pairs where the neuron boundary is crossed
        for _ in range(20):
            x1 = torch.randn(input_dim) * 5.0
            x2 = torch.randn(input_dim) * 5.0

            a1 = get_neuron_activation(x1)[neuron].item()
            a2 = get_neuron_activation(x2)[neuron].item()

            if a1 * a2 < 0:  # boundary crossed on the segment
                # Binary search to find boundary point
                lo, hi = x1.clone(), x2.clone()
                for _ in range(30):
                    mid = (lo + hi) / 2
                    a_mid = get_neuron_activation(mid)[neuron].item()
                    if a_mid * a1 > 0:
                        lo = mid
                    else:
                        hi = mid

                boundary_point = (lo + hi) / 2

                # Find another boundary point to determine the normal
                offset = torch.randn(input_dim) * 0.1
                p_plus = boundary_point + offset
                a_plus = get_neuron_activation(p_plus)[neuron].item()

                lo2, hi2 = p_plus.clone(), boundary_point.clone()
                for _ in range(30):
                    mid2 = (lo2 + hi2) / 2
                    a_mid2 = get_neuron_activation(mid2)[neuron].item()
                    if a_mid2 * a_plus > 0:
                        lo2 = mid2
                    else:
                        hi2 = mid2

                bp2 = (lo2 + hi2) / 2

                # The normal direction gives us weight row (up to sign and scale)
                normal = (boundary_point - bp2).numpy()
                W_recovered[neuron] = normal / np.linalg.norm(normal)
                break

    # Sign disambiguation: check which side gives positive activation
    for neuron in range(output_dim):
        row = torch.tensor(W_recovered[neuron], dtype=torch.float32)
        x_test = torch.randn(input_dim)
        a_test = get_neuron_activation(x_test)[neuron].item()
        pred = (row @ x_test).item()
        if (a_test > 0 and pred < 0) or (a_test < 0 and pred > 0):
            W_recovered[neuron] = -W_recovered[neuron]

    return W_recovered, b_recovered


def reconstruct_weight_magnitudes(model, W_normalized, layer_idx, input_dim, output_dim):
    """
    After recovering weight directions (unit normals), recover exact magnitudes
    by querying with scaled inputs. For ReLU: ReLU(c * Wx) = c * ReLU(Wx),
    so scaling the input reveals the weight norm through the output scale.
    """
    def get_output_norm(x):
        with torch.no_grad():
            h = x.clone()
            for i, (w, b) in enumerate(zip(model.weights, model.biases)):
                h = h @ w.T + b
                if i < layer_idx:
                    h = torch.relu(h)
                if i == layer_idx:
                    return h.norm().item()
        return 0.0

    magnitudes = []
    for neuron in range(output_dim):
        row = torch.tensor(W_normalized[neuron], dtype=torch.float32)
        x = row / row.norm()  # unit vector in weight direction
        out1 = get_output_norm(x * 1.0)
        magnitudes.append(out1 if out1 > 0 else 0.0)

    return np.array(magnitudes)
```

**Key insight:** ReLU creates piecewise linear decision regions. The boundaries between active/dead regions are hyperplanes defined by the weight rows. Finding these boundaries via binary search recovers the weight direction. This is fundamentally different from model extraction (which trains a separate student model) -- model reconstruction aims for *bit-exact* or *near-exact* weight recovery. The attack is query-efficient for small models but scales poorly to large hidden dimensions.

## Bypass

### When API Returns Only Top-1 Label (No Confidence)
- Use boundary attacks with binary search near decision boundaries
- Estimate confidence from prediction stability across slightly perturbed inputs
- Train a surrogate model on (input, label) pairs and use the surrogate's confidence

### When API Has Rate Limits
- Use transfer attacks (query surrogate, not target)
- Distribute queries across multiple API keys/sessions
- Use cached results for repeated inputs
- Prioritize informative queries near expected decision boundaries

### When Model Has Defenses (Gradient Masking)
- Use transfer attacks from undefended surrogate models
- Use black-box query attacks (boundary, HopSkipJump)
- Use C&W attack with higher kappa for better transferability
- Ensemble of surrogate models trained on similar data distribution

### When Only Logits Available (Not Probabilities)
- Convert logits to probabilities for threshold-based attacks
- Use logit magnitude differences for membership inference
- Logit values are more informative than binarized predictions

### When Model Uses Differential Privacy
- Membership inference becomes harder (DP bounds the influence of each training point)
- Increase query budget significantly (100K+ queries for meaningful results)
- Focus on outlier training data (DP protects typical points less than outliers)

## Verification

- Weight negation: recovered model generates the suppressed content (flag, secret text)
- Model inversion: reconstructed input resembles training data visually or semantically
- Encoder collision: two visually distinct inputs produce nearly identical embeddings (distance < 1e-6)
- LoRA merge: merged model generates hidden content encoded in adapter weights
- Model extraction: surrogate model achieves >95% agreement with teacher on held-out test data
- Membership inference: correctly identifies which samples were in training set
- Training data extraction: memorized text repeats across independent generations from same prefix
- Gradient leakage: recovered image matches the private training image used to compute gradients
- Attribute inference: inferred attribute matches true attribute significantly better than random (>50% accuracy for binary attributes, >25% for 4-class)
- Model reconstruction: reconstructed weights produce identical outputs to the target model on random test inputs (MSE < 1e-6 or exact activation pattern match)

## Pitfalls

- **Model architecture mismatch:** The base model architecture must match exactly for weight perturbation negation and LoRA merging; even minor differences in config (hidden size, layer count) cause dimension mismatches
- **Temperature and sampling:** For model inversion and feature visualization, low temperature produces cleaner results but may miss nuanced features; try multiple temperature values
- **Batch normalization state:** Always call `model.eval()` before attacks that require gradients through the model; `model.train()` uses batch statistics that vary with batch size
- **Gradient caching:** PyTorch caches gradients on parameters by default; use `model.zero_grad()` or `torch.no_grad()` contexts to avoid contamination
- **Determinism vs randomness:** Set `torch.manual_seed(0)` and `torch.use_deterministic_algorithms(True)` for reproducibility; non-deterministic CUDA ops make attack verification unreliable
- **Ensemble extraction:** A single student model may not capture all teacher behaviors; use ensemble of students with different architectures for comprehensive extraction
- **Query budget exhaustion:** Membership inference with LiRA requires hundreds of shadow models, each needing full training; if budget is limited, use threshold-based attacks instead
- **Memorization vs generation:** Not all high-confidence outputs indicate training data memorization; common patterns (dates, URLs, public figures) may be generated rather than memorized. Cross-verify with multiple generation attempts
- **Model update poisoning:** If the model updates over time (online learning), extraction results are snapshots that may not reflect the current state
- **Quantization effects:** QLoRA and other quantization schemes lose precision in weight deltas; dequantize before merging or expect numerical noise in the results
- **Fairness constraints vs attribute inference:** Models trained with strong fairness constraints (adversarial debiasing, equalized odds) may resist attribute inference; accuracy may be close to random
- **Proxy feature correlation:** Attribute inference exploits correlated proxy features (zip code for race, job title for gender), not the attribute itself. If proxies are removed from training data, the attack weakens
- **ReLU-only reconstruction:** Model reconstruction via boundary probing only works for ReLU-activated networks; non-ReLU activations (sigmoid, tanh, GELU) do not have exact linear boundaries
- **Pre-activation access required:** Model reconstruction requires access to intermediate pre-activation values (pre-logit layer outputs), which many production APIs do not expose
- **Numerical precision limits:** Floating-point rounding errors accumulate across layers during model reconstruction, limiting recovery precision for deep networks
- **Scalability bound:** Model reconstruction is not feasible for large models (LLMs with 7B+ parameters) due to quadratic query complexity in hidden dimensions
