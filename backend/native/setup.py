from setuptools import setup
from pybind11.setup_helpers import Pybind11Extension, build_ext

setup(
    ext_modules=[Pybind11Extension("_androshield_native", ["scanner.cpp"], cxx_std=17)],
    cmdclass={"build_ext": build_ext},
)
