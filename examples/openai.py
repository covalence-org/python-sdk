# example_usage.py
from sdk.client import Covalence
import openai

def main():
  # 1) Instantiate and authenticate in one line
  cov = Covalence(
    email="alice@acme.com",
    password="hunter2",
  )

  # 2) Register your alias
  cov.register_model(
    name="my-gpt",
    model="gpt-4o",
    provider="openai",
    api_key="sk-1234…"
  )

  # 3) Pump the token into your existing OpenAI client
  client = openai.OpenAI(
    api_key=cov.token(),
    base_url=cov.url(),
  )

  # 4) Make a chat call
  resp = client.chat.completions.create(
    model="my-gpt",
    messages=[{"role":"user","content":"Hello, how are you?"}],
  )
  print("AI says:", resp.choices[0].message.content)


if __name__ == "__main__":
  main()
