defmodule Ed25519Test do
  use ExUnit.Case
  doctest Ed25519

  test "greets the world" do
    assert Ed25519.hello() == :world
  end
end
