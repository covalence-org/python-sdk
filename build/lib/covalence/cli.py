import click
from click import Context
from requests import HTTPError

from .client import Covalence
from .exceptions import AuthenticationError, RegistrationError, RefreshError

@click.group()
@click.option(
  '--username', 'email',
  envvar='COVALENCE_EMAIL',
  prompt='Covalence username/email',
  help='Your Covalence username/email',
)
@click.option(
  '--password',
  envvar='COVALENCE_PASSWORD',
  prompt=True,
  hide_input=True,
  help='Your Covalence password',
)
@click.pass_context
def cli(ctx: Context, email: str, password: str) -> None:
  """Covalence CLI entry point."""
  try:
    ctx.obj = Covalence(email=email, password=password)
  except AuthenticationError as e:
    click.echo(f"❌ Authentication failed: {e}", err=True)
    raise SystemExit(1)

@cli.command()
def login() -> None:
  """Validate Covalence credentials without further action."""
  click.echo("✅ Login successful. Credentials validated.")

@cli.command('register-model')
@click.argument('model_name')
@click.option(
  '--model', 'model_id',
  required=True,
  help='Provider model identifier',
)
@click.option(
  '--provider',
  required=True,
  help='Model provider (e.g., openai, cohere)',
)
@click.option(
  '--api-key', 'api_key',
  default=None,
  help='Raw provider API key',
)
@click.option(
  '--custom-api-url', 'custom_api_url',
  default=None,
  help='Custom provider API URL',
)
@click.pass_context
def register_model(
  ctx: Context,
  model_name: str,
  model_id: str,
  provider: str,
  api_key: str | None,
  custom_api_url: str | None,
) -> None:
  """Register a new model with Covalence API."""
  client: Covalence = ctx.obj
  try:
    result = client.register_model(
      name=model_name,
      model=model_id,
      provider=provider,
      api_key=api_key,
      custom_api_url=custom_api_url,
    )
    click.echo(f"✅ Model registered: {result}")
  except RegistrationError as e:
    click.echo(f"❌ Registration error: {e}", err=True)
    raise SystemExit(1)

@cli.command('user-details')
@click.pass_context
def user_details(ctx: Context) -> None:
  """Fetch and display current user details."""
  client: Covalence = ctx.obj
  try:
    details = client.get_user_details()
    click.echo(details)
  except (AuthenticationError, RefreshError, HTTPError) as e:
    click.echo(f"❌ Could not retrieve user details: {e}", err=True)
    raise SystemExit(1)

if __name__ == '__main__':
  cli()