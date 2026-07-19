defmodule MetamorphicLog.MixProject do
  use Mix.Project

  @version "0.1.8"
  @repo_url "https://github.com/moss-piglet/metamorphic_log"

  def project do
    [
      app: :metamorphic_log,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @repo_url,
      homepage_url: @repo_url,
      docs: docs(),
      aliases: aliases()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp description do
    "Elixir client for the metamorphic-log transparency-log engine: " <>
      "inclusion/consistency proofs, C2SP signed-note + checkpoint verification " <>
      "(Ed25519 + hybrid post-quantum), CONIKS lookup/absence proofs, " <>
      "namespace-policy verification, ingestion primitives, and anchoring. Precompiled Rust NIFs."
  end

  defp deps do
    [
      {:rustler, "~> 0.38.0", runtime: false},
      {:rustler_precompiled, "~> 0.8"},
      {:metamorphic_crypto, "~> 0.8.2", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      name: "metamorphic_log",
      licenses: ["MIT", "Apache-2.0"],
      links: %{
        "GitHub" => @repo_url,
        "Changelog" => "#{@repo_url}/blob/main/CHANGELOG.md",
        "Engine (Rust crate)" => "https://github.com/moss-piglet/metamorphic-log"
      },
      files: ~w[
        lib
        docs
        native/metamorphic_log_nif/Cargo.toml
        native/metamorphic_log_nif/Cargo.lock
        native/metamorphic_log_nif/src
        checksum-*.exs
        mix.exs
        README.md
        CHANGELOG.md
        LICENSE-MIT
        LICENSE-APACHE
        .formatter.exs
      ],
      # Maintainer-only release tooling; not useful to package consumers.
      exclude_patterns: ["lib/mix/tasks/metamorphic_log.release.ex"]
    ]
  end

  defp docs do
    [
      main: "MetamorphicLog",
      extras: [
        "README.md",
        "docs/verification-guide.md",
        "CHANGELOG.md"
      ],
      groups_for_modules: [
        Proofs: [MetamorphicLog.Proof],
        Checkpoints: [MetamorphicLog.Checkpoint, MetamorphicLog.Note],
        "Key Transparency (CONIKS)": [MetamorphicLog.Coniks, MetamorphicLog.Commitment],
        "Key Transparency (KEYTRANS)": [MetamorphicLog.Keytrans],
        "Namespace Policy": [MetamorphicLog.Policy],
        Leaves: [MetamorphicLog.Leaf],
        Ingestion: [MetamorphicLog.Ingest],
        Anchoring: [MetamorphicLog.Anchor]
      ]
    ]
  end

  defp aliases do
    [
      fmt: ["format", "cmd cargo fmt --manifest-path native/metamorphic_log_nif/Cargo.toml"]
    ]
  end
end
