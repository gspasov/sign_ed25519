defmodule Ed25519Test do
  use ExUnit.Case
  doctest Ed25519

  test "keypair_creation_and_size_test" do
    assert %{public: pubkey, private: privkey} = Ed25519.keypair()
    assert byte_size(pubkey) == 32
    assert byte_size(privkey) == 64
  end

  test "signing_message_test" do
    assert {:error, {:invalid_type, _}} = Ed25519.sign(0, <<>>)
    assert {:error, {:invalid_type, _}} = Ed25519.sign(0.1, <<>>)

    assert {:error, {:invalid_type, _}} = Ed25519.sign(<<>>, 0)
    assert {:error, {:invalid_type, _}} = Ed25519.sign(<<>>, 0.1)
    assert {:error, {:invalid_type, _}} = Ed25519.sign(<<>>, [])

    assert {:error, {:invalid_keysize, _}} = Ed25519.sign("", <<0::128>>)
    assert {:error, {:invalid_keysize, _}} = Ed25519.sign("", <<0::256>>)
    assert {:error, {:invalid_keysize, _}} = Ed25519.sign([], <<>>)

    assert signature(:sign_test) == Ed25519.sign("", <<0::512>>)
  end

  test "verifying_signature_test" do
    assert {:error, {:invalid_type, _}} = Ed25519.verify(0, 0, <<>>)
    assert {:error, {:invalid_type, _}} = Ed25519.verify(0.1, 0, <<>>)
    assert {:error, {:invalid_type, _}} = Ed25519.verify([], 0, <<>>)

    assert {:error, {:invalid_type, _}} = Ed25519.verify(<<>>, <<>>, 0)
    assert {:error, {:invalid_type, _}} = Ed25519.verify(<<>>, <<>>, 0.1)
    assert {:error, {:invalid_type, _}} = Ed25519.verify(<<>>, <<>>, [])

    assert {:error, {:invalid_keysize, _}} = Ed25519.verify(<<>>, [], <<0::512>>)
    assert {:error, {:invalid_keysize, _}} = Ed25519.verify(<<>>, <<>>, <<0::128>>)

    assert {:error, {:invalid_keysize, _}} = Ed25519.verify(<<1, 2>>, <<>>, <<0::512>>)
    assert {:error, {:failed_verification, _}} = Ed25519.verify(<<1, 2>>, <<>>, <<0::256>>)

    assert {:error, {:invalid_keysize, _}} =
             Ed25519.verify(<<"signature">>, <<"message">>, <<0::64>>)

    assert {:error, {:invalid_keysize, _}} = Ed25519.verify(<<"signature">>, <<>>, <<0::128>>)

    assert :ok == Ed25519.verify(signature(:verify_test), message(), pubkey())
  end

  def signature(:sign_test) do
    <<143, 137, 91, 60, 175, 226, 201, 80, 96, 57, 208, 226, 166, 99, 130, 86, 128, 4, 103, 79,
      232, 210, 55, 120, 80, 146, 228, 13, 106, 175, 72, 62, 251, 208, 58, 45, 221, 160, 82, 52,
      104, 53, 253, 203, 52, 132, 245, 239, 158, 2, 198, 191, 195, 184, 110, 251, 116, 254, 56,
      175, 99, 48, 69, 1>>
  end

  def signature(:verify_test) do
    <<175, 60, 243, 98, 216, 161, 161, 83, 139, 93, 128, 81, 150, 25, 106, 42, 145, 250, 44, 194,
      190, 225, 194, 85, 143, 41, 142, 226, 65, 220, 48, 72, 71, 16, 245, 77, 11, 148, 187, 21,
      26, 115, 64, 6, 29, 81, 8, 90, 219, 74, 240, 186, 64, 49, 155, 86, 117, 205, 64, 202, 252,
      56, 211, 3>>
  end

  def pubkey do
    <<9, 220, 178, 185, 40, 38, 43, 196, 121, 33, 44, 3, 182, 3, 63, 63, 101, 124, 0, 191, 187,
      99, 194, 189, 93, 47, 190, 29, 16, 11, 130, 252>>
  end

  def message, do: <<"message">>
end
