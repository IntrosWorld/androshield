// Experimental ASCII fast paths. Unicode and numerically ambiguous cases return
// to the existing Python implementation, preserving its exact regex semantics.
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <array>
#include <cmath>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace py = pybind11;
constexpr std::size_t max_batch = 1000000;

static bool word(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}
static void validate(const py::list &strings) {
    if (strings.size() > max_batch) throw py::value_error("batch too large");
    for (auto item : strings) {
        if (!PyUnicode_CheckExact(item.ptr())) throw py::type_error("expected builtin strings");
    }
}

static py::tuple keyword_stats(const py::list &strings, const std::vector<std::string> &keywords) {
    validate(strings);
    if (keywords.size() > 128) throw py::value_error("too many keywords");
    for (const auto &key : keywords) {
        if (key.empty() || !word(key.front()) || !word(key.back()))
            throw py::value_error("keywords need word boundaries");
        for (unsigned char c : key) {
            if (c > 127 || (c >= 'A' && c <= 'Z')) throw py::value_error("expected lowercase ASCII keywords");
        }
    }
    std::vector<std::size_t> counts(keywords.size(), 0);
    std::vector<py::ssize_t> first(keywords.size(), -1), fallback;
    std::array<char, 4000> buffer;
    for (py::ssize_t index = 0; index < strings.size(); ++index) {
        PyObject *item = strings[index].ptr();
        const auto length = PyUnicode_GET_LENGTH(item);
        if (!length || length > 4000) continue;
        if (!PyUnicode_IS_ASCII(item)) { fallback.push_back(index); continue; }
        Py_ssize_t bytes = 0;
        const char *data = PyUnicode_AsUTF8AndSize(item, &bytes);
        if (!data) throw py::error_already_set();
        for (Py_ssize_t i = 0; i < bytes; ++i)
            buffer[i] = data[i] >= 'A' && data[i] <= 'Z' ? data[i] + ('a' - 'A') : data[i];
        std::string_view text(buffer.data(), static_cast<std::size_t>(bytes));
        for (std::size_t k = 0; k < keywords.size(); ++k) {
            const auto &key = keywords[k];
            std::size_t start = 0;
            while ((start = text.find(key, start)) != std::string_view::npos) {
                const auto end = start + key.size();
                if ((start == 0 || !word(text[start - 1])) &&
                    (end == text.size() || !word(text[end]))) {
                    if (counts[k]++ == 0) first[k] = index;
                    break; // Python search counts presence once per string.
                }
                ++start;
            }
        }
    }
    return py::make_tuple(counts, first, fallback);
}

static py::tuple entropy_stats(const py::list &strings) {
    validate(strings);
    std::size_t candidates = 0, high = 0;
    std::vector<py::ssize_t> fallback;
    for (py::ssize_t index = 0; index < strings.size(); ++index) {
        PyObject *item = strings[index].ptr();
        const auto length = PyUnicode_GET_LENGTH(item);
        if (length < 24 || length > 512) continue;
        if (!PyUnicode_IS_ASCII(item)) { fallback.push_back(index); continue; }
        Py_ssize_t bytes = 0;
        const char *data = PyUnicode_AsUTF8AndSize(item, &bytes);
        if (!data) throw py::error_already_set();
        std::array<unsigned int, 128> counts{};
        std::vector<unsigned char> order;
        order.reserve(128);
        bool space = false;
        for (Py_ssize_t i = 0; i < bytes; ++i) {
            const auto c = static_cast<unsigned char>(data[i]);
            if (c == ' ') { space = true; break; }
            if (counts[c]++ == 0) order.push_back(c);
        }
        if (space) continue;
        double entropy = 0.0;
        for (auto c : order) {
            const double probability = static_cast<double>(counts[c]) / static_cast<double>(length);
            entropy -= probability * std::log2(probability);
        }
        // libm rounding must not change the rule at its 4.5-bit boundary.
        if (std::abs(entropy - 4.5) < 1e-12) { fallback.push_back(index); continue; }
        ++candidates;
        if (entropy > 4.5) ++high;
    }
    return py::make_tuple(high, candidates, fallback);
}

PYBIND11_MODULE(_androshield_native, module) {
    module.doc() = "Experimental bounded ASCII scan kernels; no APK execution or parsing";
    module.attr("API_VERSION") = 1;
    // Keep the GIL: the functions borrow immutable Python Unicode buffers.
    module.def("keyword_stats", &keyword_stats);
    module.def("entropy_stats", &entropy_stats);
}
