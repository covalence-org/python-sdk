from covalence import Covalence

# 1) one‑line instantiation
covalence = Covalence(
  email="alice@acme.com",
  password="hunter2",
)

# 2) register their model alias
covalence.register_model(name="my-gpt", model="gpt-4o", provider="openai")

# 3) now set up your client exactly as usual:
import openai

client = openai.OpenAI(
  api_key=covalence.get_token(),
  base_url="https://covalence.run/v1"  # Point to our proxy
)

# Make a request using the custom model name
response = client.chat.completions.create(
  model="my-gpt4",  # Use the custom name we registered
  messages=[{"role": "user", "content": "Hello, how are you?"}],
)

print("\nOpenAI Response:")
print(response.choices[0].message.content)

