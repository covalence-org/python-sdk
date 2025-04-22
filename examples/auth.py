# example_usage.py
from covalence.client import Covalence
from dotenv import load_dotenv
import os
import logging
import time

load_dotenv()
# try signing up

def try_sign_up():
  logging.basicConfig(level=logging.INFO)
  logger = logging.getLogger(__name__)
  logger.info("Logging is enabled")

  client = Covalence.sign_up(
    email="alialhamadani72@gmail.com",
    password="hunter2"
  )

  print(client.get_user_details())

def try_login_and_refresh():
  logging.basicConfig(level=logging.INFO)
  logger = logging.getLogger(__name__)
  logger.info("Logging is enabled")

  client = Covalence(
    email="alialhamadani72@gmail.com",
    password="hunter2"
  )

  print(client.get_user_details())

  # Try refresh
  print(client._session.expires_at)
  time.sleep(1) # Pause before refresh
  client._refresh(force=True)
  print(client._session.expires_at)




if __name__ == "__main__":
  try_login_and_refresh()