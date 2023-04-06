#include "pprf/ggm_pprf.h"
#include "secure_byte_buffer.h"
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <sys/stat.h>
std::vector<Tag> getRands() {
    std::vector<Tag> randVec;
    std::ifstream rands("rands.txt", std::ifstream::in);
    std::string line;
    if (!rands.is_open()) {
        std::cerr << "File could not be read.";
        throw std::exception();
    }
    while (std::getline(rands, line)) {
        if (randVec.size() % 10000 == 0) {
            std::cout << "-";
        }
        randVec.emplace_back(line);
    }
    std::cout << std::endl;
    return randVec;
}

std::string writeResults(std::vector<std::tuple<int, size_t, double>> &serializationSizes, int tagsize) {
    std::time_t time = std::time(nullptr);
    mkdir("out", 0777);
    std::string path = "out/serializationBenchmark_tagsize" + std::to_string(tagsize) + std::string(std::asctime(std::localtime(&time))) + ".txt";
    std::ofstream out(path, std::ofstream::out);
    out << "punc"
        << "\t"
        << "size"
        << "\t"
        << "time"
        << std::endl;
    for (auto res: serializationSizes) {
        out << std::get<0>(res) << "\t" << std::get<1>(res) << "\t" << std::get<2>(res) << std::endl;
    }
    out.close();
    return path;
}

int main() {
    std::cout << "Starting benchmark." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    GGM_PPRF prf(PPRFKey(128, 16));
    std::vector<Tag> rands = getRands();
    std::cout << "Read " << rands.size() << " lines." << std::endl;
    std::vector<std::tuple<int, size_t, double>> serializationSizes;
    auto prev = std::chrono::high_resolution_clock::now();
    for (auto &rand: rands) {
        prf.punc(rand >> (MAX_TAG_LEN - prf.tagLen()));
        if (prf.getNumPuncs() % 10 == 0) {
            auto curr = std::chrono::high_resolution_clock::now();
            SecureByteBuffer serialized = prf.serializeKey();
            auto t = (curr - prev).count() / pow(10, 6);
            prev = std::chrono::high_resolution_clock::now();
            serializationSizes.emplace_back(std::tuple<int, size_t, long>(prf.getNumPuncs(), serialized.size(), t));
            std::cout << "Size after " << prf.getNumPuncs() << " punctures is \t" << serialized.size() << ",\t time for 10 puncs = " << t << std::endl;
        }
    }
    std::cout << std::endl;

    auto end = std::chrono::high_resolution_clock::now();
    std::string path = writeResults(serializationSizes, prf.tagLen());
    std::cout << "Finished benchmark." << std::endl;
    std::cout << "Execution time: " << (end - start).count() / pow(10, 6) << std::endl;
    std::cout << "Output file at: " << path;
}