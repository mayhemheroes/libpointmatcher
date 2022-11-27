#include <cstdlib>
#include <fstream>

#include "pointmatcher/PointMatcher.h"

#include "FuzzedDataProvider.h"

typedef PointMatcher<float> PM;
typedef PM::DataPoints DP;

std::string create_file(FuzzedDataProvider& fdp) {
    std::string chosen_extension = fdp.PickValueInArray({".csv", ".vtk"});
    std::size_t file_len = fdp.ConsumeIntegralInRange<int>(0, 10000);
    std::string fuzz_file_name = std::tmpnam(nullptr) + chosen_extension;

    // Write fuzzer data to temporary file
    std::ofstream fuzz_file{};
    fuzz_file.open(fuzz_file_name, std::ios::binary | std::ios::out);
    fuzz_file << fdp.ConsumeBytesAsString(file_len);
    fuzz_file.close();

    return fuzz_file_name;
}

extern "C" __attribute__((unused)) int LLVMFuzzerTestOneInput(const uint8_t *fuzz_data, size_t size) {
    FuzzedDataProvider fdp(fuzz_data, size);

    try {
        std::string ref_file_name = create_file(fdp);
        std::string data_file_name = create_file(fdp);

        const DP ref = DP::load(ref_file_name);
        const DP data = DP::load(data_file_name);

        PM::ICP icp;
        icp.setDefault();
//
        PM::TransformationParameters T = icp(data, ref);
//
        DP data_out(data);
        icp.transformations.apply(data_out, T);

        // Delete temporary file
        std::remove(ref_file_name.c_str());
        std::remove(data_file_name.c_str());
    } catch (const PM::ConvergenceError& e) {
        return -1;
    } catch (boost::exception &e) {
        return -1;
    } catch (std::runtime_error &e) {
        if (std::string(e.what()).find("magic header") != std::string::npos ||
            std::string(e.what()).find("Wrong file type") != std::string::npos ||
            std::string(e.what()).find("Mayhem") != std::string::npos ||
            std::string(e.what()).find("CSV parse") != std::string::npos) {
            return -1;
        } else {
            throw;
        }
    }
    return 0;
}