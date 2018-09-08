defmodule Ed25519 do
  @moduledoc """
  Key manager for key creation, signatures and verifying usign Ed25519
  """

  @type pubkey :: binary()
  @type privkey :: binary()
  @type signature :: binary()

  @pubkey_size 32
  @privkey_size 64

  @doc """
  Creates a pub/priv keypair

  ## Example
      iex> Ed25519.keypair()
      iex> %{public: pubkey, private: privkey}
  """
  @spec keypair() :: %{public: binary(), private: binary()}
  def keypair() do
    %{public: pubkey, secret: privkey} = :enacl.sign_keypair()
    %{public: pubkey, private: privkey}
  end

  @doc """
  Creates a signature from given message and privkey

  ## Example
      iex> Ed25519.sign(<<0, 1, 2>>, <<0::512>>)
      iex> <<132, 245, 239, 158, 2, ...>>

      iex> Ed25519.sign("message", <<0::512>>)
      iex> <<54, 123, 211, 4, 76, ...>>

      iex> Ed25519.sign("message", <<0::256>>)
      iex> {:error, :wrong_pivkey_size}
  """
  @spec sign(binary(), privkey()) ::
          signature()
          | {:error,
             :message_not_binary
             | :privkey_not_binary
             | :wrong_privkey_size}
  def sign(message, _privkey) when not is_binary(message) do
    {:error, :message_not_binary}
  end

  def sign(_message, privkey) when not is_binary(privkey) do
    {:error, :privkey_not_binary}
  end

  def sign(_message, privkey)
      when byte_size(privkey) != @privkey_size do
    {:error, :wrong_privkey_size}
  end

  def sign(message, privkey) do
    :enacl.sign_detached(message, privkey)
  end

  @doc """
  Verifies a signature from given signature message and pubkey

  ## Example
      iex> Ed25519.verify(<<0, 1, 2>>, "message", <<0::256>>)
      iex> :ok

      iex> Ed25519.verify(<<0, 1, 3>>, "message", <<0::256>>)
      iex> {:error, :failed_verification}

      iex> Ed25519.verify("message", <<0::512>>)
      iex> {:error, :wrong_pivkey_size}
  """
  @spec verify(signature(), binary(), pubkey()) ::
          :ok
          | {:error,
             :failed_verification
             | :signature_not_binary
             | :pubkey_not_binary
             | :wrong_pubkey_size}
  def verify(sign, _message, _pubkey) when not is_binary(sign) do
    {:error, :signature_not_binary}
  end

  def verify(_sign, _message, pubkey) when not is_binary(pubkey) do
    {:error, :pubkey_not_binary}
  end

  def verify(_sign, _message, pubkey)
      when byte_size(pubkey) != @pubkey_size do
    {:error, :wrong_pubkey_size}
  end

  def verify(sign, message, pubkey) do
    case :enacl.sign_verify_detached(sign, message, pubkey) do
      {:ok, _} -> :ok
      err = {:error, :failed_verification} -> err
    end
  end
end
