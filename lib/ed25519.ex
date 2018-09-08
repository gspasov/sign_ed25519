defmodule Ed25519 do
  @moduledoc """
  Key manager for key creation, signatures and verifying usign Ed25519
  """

  @type pubkey() :: binary()
  @type privkey() :: binary()
  @type signature() :: binary()

  @pubkey_size 32
  @privkey_size 64

  @doc """
  Creates a pub/priv keypair

  ## Example
      Ed25519.keypair()
      %{public: <<>>, private: <<>>}
  """
  @spec keypair() :: %{public: binary(), private: binary()}
  def keypair() do
    %{public: pubkey, secret: privkey} = :enacl.sign_keypair()
    %{public: pubkey, private: privkey}
  end

  @doc """
  Creates a signature from given message and privkey

  ## Example
      Ed25519.sign(<<0, 1, 2>>, <<0::512>>)
      <<132, 245, 239, 158, 2>>

      Ed25519.sign("message", <<0::512>>)
      <<54, 123, 211, 4, 76>>

      iex> Ed25519.sign("message", <<0::256>>)
      {:error, {:invalid_keysize, "Private key can only be of size 64 bytes"}}
  """
  @spec sign(binary(), privkey()) ::
          signature()
          | {:error, {:invalid_type | :invalid_keysize, String.t()}}
  def sign(message, _privkey)
      when not is_binary(message) and not is_list(message) do
    {:error, {:invalid_type, "Message can only be of type binary or list"}}
  end

  def sign(_message, privkey) when not is_binary(privkey) do
    {:error, {:invalid_type, "Private key can only be of type binary"}}
  end

  def sign(_message, privkey)
      when byte_size(privkey) != @privkey_size do
    {:error, {:invalid_keysize, "Private key can only be of size 64 bytes"}}
  end

  def sign(message, privkey) do
    :enacl.sign_detached(message, privkey)
  end

  @doc """
  Verifies a signature from given signature message and pubkey

  ## Example
      Ed25519.verify(<<0, 1, 2>>, "message", <<0::256>>)
      :ok

      Ed25519.verify(<<7, 2, 4>>, [], <<0::256>>)
      :ok

      iex> Ed25519.verify(<<0, 1, 3>>, "message", <<0::256>>)
      {:error, {:failed_verification, "Can't verify signature with the given data"}}

      iex> Ed25519.verify(<<1, 2, 3>>, "message", <<0::512>>)
      {:error, {:invalid_keysize, "Public key can only be of size 32 bytes"}}
  """
  @spec verify(signature(), binary(), pubkey()) ::
          :ok
          | {:error,
             {:failed_verification
              | :invalid_type
              | :invalid_keysize, String.t()}}
  def verify(sign, _message, _pubkey) when not is_binary(sign) do
    {:error, {:invalid_type, "Signature can only be of type binary"}}
  end

  def verify(_sign, message, _pubkey)
      when not is_binary(message) and not is_list(message) do
    {:error, {:invalid_type, "Message can only be of type binary or list"}}
  end

  def verify(_sign, _message, pubkey) when not is_binary(pubkey) do
    {:error, {:invalid_type, "Public key can only be of type binary"}}
  end

  def verify(_sign, _message, pubkey)
      when byte_size(pubkey) != @pubkey_size do
    {:error, {:invalid_keysize, "Public key can only be of size 32 bytes"}}
  end

  def verify(sign, message, pubkey) do
    case :enacl.sign_verify_detached(sign, message, pubkey) do
      {:ok, _} -> :ok
      _ -> {:error, {:failed_verification, "Can't verify signature with the given data"}}
    end
  end
end
