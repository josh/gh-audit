{ pkgs, lib, ... }:
{
  env.GREET = "devenv";

  packages = [
    pkgs.git
    pkgs.gh
  ];

  languages.python = {
    enable = true;
    version = "3.12";
    venv.enable = true;
    venv.requirements = ./requirements.txt;
    uv.enable = true;
  };

  enterTest = ''
    echo "Running tests"
    git --version | grep --color=auto "${pkgs.git.version}"
  '';

  pre-commit.hooks = {
    actionlint.enable = true;
    check-toml.enable = true;
    check-yaml.enable = true;
    # mypy.enable = true;
    nixfmt-rfc-style.enable = true;
    ruff-format.enable = true;
    ruff.enable = true;
  };
}
