# `pytester` runs a throwaway pytest inside this one, which is the only way to
# assert on an *outcome* the fixture produces at teardown rather than on an
# exception it raises.
pytest_plugins = ["pytester"]
