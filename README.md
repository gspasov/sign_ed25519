# sign_ed25519
Key manager for signatures using Ed25519

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `ed25519` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ed25519, "~> 0.1.0"}
  ]
end

## Usage

   ### Creating public/private keypair
   
   ```elixir
   %{public: pubkey, private: privkey} = Ed25519.keypair()
   ```

   ### Signing a message

   ```elixir
   signature = Ed25519.sign(message, private_key)
   ```

   ### Verifying a message

   ```elixir
   Ed25519.verify(signature, message, public_key)
   ``` 
```
