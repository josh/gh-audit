{
  lib,
  python3Packages,
}:
python3Packages.buildPythonApplication {
  pname = "gh-audit";
  version = "0.1.0";
  pyproject = true;

  src = ./.;

  build-system = with python3Packages; [
    setuptools
  ];

  dependencies = with python3Packages; [
    click
    pygithub
    pyyaml
  ];

  meta = {
    description = "Personal GitHub repository meta linting tool for consistent configuration";
    homepage = "https://github.com/josh/gh-audit";
    license = lib.licenses.mit;
    platforms = lib.platforms.all;
    mainProgram = "gh-audit";
  };
}
