/*
 * Copyright 2018 CryptoGraphics ( CrGraphics@protonmail.com )
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version. See LICENSE for more details.
 */

#ifndef AppAllium_INCLUDE_ONCE
#define AppAllium_INCLUDE_ONCE

#include <vector>
#include <string>
#include <lyclCore/CLUtils.hpp>
#include <cstring> // memset
#include <chrono>

namespace lycl
{
    struct KernelData
    {
        uint32_t uH0;
        uint32_t uH1;
        uint32_t uH2;
        uint32_t uH3;
        uint32_t uH4;
        uint32_t uH5;
        uint32_t uH6;
        uint32_t uH7;

        uint32_t in16;
        uint32_t in17;
        uint32_t in18;

        cl_ulong htArg;
    };

    struct alliumHash { uint32_t h[8]; };

    //-----------------------------------------------------------------------------
    // AppLyra2REv2 class declaration.
    //-----------------------------------------------------------------------------
    class AppAllium
    {
    public:
        inline AppAllium();

        //! initalization is required before using all other functions.
        inline bool onInit(const device& in_device);
        //! compute (work_size) hashes, starting from the (first_nonce) and checks hTarg.
        //! NOTE: hash results are not saved from the latest pass. Only hTarg result.
        inline void onRun(uint32_t first_nonce, size_t work_size);
        //! destroy context and free resources.
        inline void onDestroy();
        //! must be called at least once, before (onRun())
        inline void setKernelData(const KernelData& kernel_data);
        //! returns all hashes. Very slow. Used for validation
        inline void getHashes(std::vector<alliumHash>& lyra_hashes);
        //! get result based on Htarg test.
        inline void getHtArgTestResultAndSize(uint32_t& out_nonce, uint32_t& out_dbgCount);
        //! get Htarg test result buffer content
        inline void getHtArgTestResults(std::vector<uint32_t>& out_htargs, size_t num_elements, size_t offset_elem);
        //! returns hash at specific index, useful for host side validation.
        inline void getLatestHashResultForIndex(uint32_t index, alliumHash& out_hash);
        //! clear hTarg result buffer.
        inline void clearResult(size_t num_elements);

    private:
        size_t m_maxWorkSize;
        cl_context m_clContext;
        cl_command_queue m_clCommandQueue;
        // blake32
        cl_program m_clProgramBlake32;
        cl_kernel m_clKernelBlake32;
        // keccakF1600
        cl_program m_clProgramKeccakF1600;
        cl_kernel m_clKernelKeccakF1600;
        // cubeHash256
        cl_program m_clProgramCubeHash256;
        cl_kernel m_clKernelCubeHash256;
        // lyra441p1
        cl_program m_clProgramLyra441p1;
        cl_kernel m_clKernelLyra441p1;
        // lyra441p2
        cl_program m_clProgramLyra441p2;
        cl_kernel m_clKernelLyra441p2;
        // lyra441p3
        cl_program m_clProgramLyra441p3;
        cl_kernel m_clKernelLyra441p3;
        // // lyra2
        // cl_program m_clProgramLyra2;
        // cl_kernel m_clKernelLyra2;
        // skein
        cl_program m_clProgramSkein;
        cl_kernel m_clKernelSkein;
        // groestl256Htarg
        cl_program m_clProgramGroestl256Htarg;
        cl_kernel m_clKernelGroestl256Htarg;
        // buffers
        cl_mem m_clMemHashStorage;
        cl_mem m_clMemLyraStates;
        cl_mem m_clMemHtArgResult;
    };
    //-----------------------------------------------------------------------------
    // AppAllium class inline methods implementation.
    //-----------------------------------------------------------------------------
    inline AppAllium::AppAllium() { }
    //-----------------------------------------------------------------------------
    inline bool AppAllium::onInit(const device& in_device)
    {
        std::string deviceName;
        m_maxWorkSize = in_device.workSize; 
        cl_int errorCode = CL_SUCCESS;

        //-------------------------------------
        // Get device name for debug log.
        size_t infoSize;
        clGetDeviceInfo(in_device.clId, CL_DEVICE_NAME, 0, NULL, &infoSize);
        //clDevice.name.resize(infoSize - 1);
        deviceName.resize(infoSize);
        clGetDeviceInfo(in_device.clId, CL_DEVICE_NAME, infoSize, (void *)deviceName.data(), NULL);
        deviceName.pop_back();

        //-------------------------------------
        // Create an OpenCL context
        cl_context_properties contextProperties[] =
        {
            CL_CONTEXT_PLATFORM,
            (cl_context_properties)in_device.clPlatformId,
            0
        };
        // create 1 context for each device
        m_clContext = clCreateContext(contextProperties, 1, &in_device.clId, nullptr, nullptr, &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create an OpenCL context. Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        //-------------------------------------
        // Create an OpenCL command queue
        //clCreateCommandQueue() // deprecated in 2.0
        //m_clCommandQueue = clCreateCommandQueue(m_clContext, in_device.clId, 0, &errorCode);
        m_clCommandQueue = clCreateCommandQueueWithProperties(m_clContext, in_device.clId, nullptr, &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create a command queue. Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        
        //-------------------------------------
        // Create buffers
        m_clMemHashStorage = clCreateBuffer(m_clContext, CL_MEM_READ_WRITE, sizeof(alliumHash)*m_maxWorkSize, nullptr, &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create a hash storage buffer. Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        m_clMemLyraStates = clCreateBuffer(m_clContext, CL_MEM_READ_WRITE, sizeof(alliumHash)*m_maxWorkSize*4, nullptr, &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create a lyra state buffer. Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        m_clMemHtArgResult = clCreateBuffer(m_clContext, CL_MEM_READ_WRITE, sizeof(uint32_t) * (m_maxWorkSize + 1), nullptr, &errorCode); // Too much, but 100% robust.
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create an HTarg result buffer. Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        // Result counter must be initialized to 0.
        clearResult(1);

        //-------------------------------------
        // Create an OpenCL blake32 kernel
        m_clProgramBlake32 = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/blake32/blake32.cl");
        if (m_clProgramBlake32 == NULL)
        {
            std::cerr << "Failed to create CL program from source(blake32). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        m_clKernelBlake32 = clCreateKernel(m_clProgramBlake32, "blake32", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create kernel(blake32). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelBlake32, 0, sizeof(cl_mem), &m_clMemHashStorage);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(blake32). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        //-------------------------------------
        // Create an OpenCL keccak kernel
        m_clProgramKeccakF1600 = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/keccakF1600/keccakF1600.cl");
        if (m_clProgramKeccakF1600 == NULL)
        {
            std::cerr << "Failed to create CL program from source(keccakF1600). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        m_clKernelKeccakF1600 = clCreateKernel(m_clProgramKeccakF1600, "keccakF1600", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create kernel(keccakF1600). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelKeccakF1600, 0, sizeof(cl_mem), &m_clMemHashStorage);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(keccakF1600). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
		
        // //-------------------------------------
        // // Create an OpenCL lyra2 kernel
        // m_clProgramLyra2 = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/lyra2/lyra2.cl");
        // if (m_clProgramLyra2 == NULL)
        // {
            // std::cerr << "Failed to create CL program from source(lyra2). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            // return false;
        // }

        // m_clKernelLyra2 = clCreateKernel(m_clProgramLyra2, "lyra2", &errorCode);
        // if (errorCode != CL_SUCCESS)
        // {
            // std::cerr << "Failed to create kernel(lyra2). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            // return false;
        // }
        // errorCode = clSetKernelArg(m_clKernelLyra2, 0, sizeof(cl_mem), &m_clMemHashStorage);
        // if (errorCode != CL_SUCCESS)
        // {
            // std::cerr << "Error setting kernel argument(0) inside kernel(lyra2). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            // return false;
        // }

        //-------------------------------------
        // Create an OpenCL cubeHash kernel
        m_clProgramCubeHash256 = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/cubeHash256/cubeHash256.cl");
        if (m_clProgramCubeHash256 == NULL)
        {
            std::cerr << "Failed to create CL program from source(cubeHash256). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        m_clKernelCubeHash256 = clCreateKernel(m_clProgramCubeHash256, "cubeHash256", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create kernel(cubeHash256). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelCubeHash256, 0, sizeof(cl_mem), &m_clMemHashStorage);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(cubeHash256). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        //-------------------------------------
        // Create an OpenCL lyra441p1 kernel
        m_clProgramLyra441p1 = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/lyra2phi2/lyra2p1.cl");
        if (m_clProgramLyra441p1 == NULL)
        {
            std::cerr << "Failed to create CL program from source(lyra441p1). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        m_clKernelLyra441p1 = clCreateKernel(m_clProgramLyra441p1, "lyra441p1", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create kernel(lyra441p1). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelLyra441p1, 0, sizeof(cl_mem), &m_clMemHashStorage);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(lyra441p1). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelLyra441p1, 1, sizeof(cl_mem), &m_clMemLyraStates);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(1) inside kernel(lyra441p1). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        //-------------------------------------
        // Create an OpenCL lyra441p2 kernel
		m_clProgramLyra441p2 = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/lyra2phi2/lyra2p2.cl");
		if (m_clProgramLyra441p2 == NULL)
		{
			std::cerr << "Failed to create CL program from source(lyra441p2). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
			return false;
		}

        m_clKernelLyra441p2 = clCreateKernel(m_clProgramLyra441p2, "lyra441p2", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create kernel(lyra441p2). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelLyra441p2, 0, sizeof(cl_mem), &m_clMemLyraStates);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(lyra441p2). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        //-------------------------------------
        // Create an OpenCL lyra441p3 kernel
        m_clProgramLyra441p3 = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/lyra2phi2/lyra2p3.cl");
        if (m_clProgramLyra441p3 == NULL)
        {
            std::cerr << "Failed to create a CL program from source(lyra441p3). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        m_clKernelLyra441p3 = clCreateKernel(m_clProgramLyra441p3, "lyra441p3", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create a kernel(lyra441p3). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelLyra441p3, 0, sizeof(cl_mem), &m_clMemHashStorage);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(lyra441p3). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelLyra441p3, 1, sizeof(cl_mem), &m_clMemLyraStates);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(1) inside kernel(lyra441p3). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }

        //-------------------------------------
        // Create an OpenCL skein kernel
        m_clProgramSkein = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/skein/skein.cl");
        if (m_clProgramSkein == NULL)
        {
            std::cerr << "Failed to create CL program from source(skein). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        m_clKernelSkein = clCreateKernel(m_clProgramSkein, "skein", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create kernel(skein). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelSkein, 0, sizeof(cl_mem), &m_clMemHashStorage);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(skein). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        
        //-------------------------------------
        // Create an OpenCL groestl256(htarg) kernel
        m_clProgramGroestl256Htarg = cluCreateProgramFromFile(m_clContext, in_device.clId, "kernels/groestl256/groestl256_htarg.cl");
        if (m_clProgramGroestl256Htarg == NULL)
        {
            std::cerr << "Failed to create CL program from source(groestl256Htarg). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        m_clKernelGroestl256Htarg = clCreateKernel(m_clProgramGroestl256Htarg, "groestl256", &errorCode);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Failed to create kernel(groestl256Htarg). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelGroestl256Htarg, 0, sizeof(cl_mem), &m_clMemHashStorage);
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(0) inside kernel(groestl256Htarg). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        errorCode = clSetKernelArg(m_clKernelGroestl256Htarg, 1, sizeof(cl_mem), &m_clMemHtArgResult); 
        if (errorCode != CL_SUCCESS)
        {
            std::cerr << "Error setting kernel argument(1) inside kernel(groestl256Htarg). Device(" << deviceName << ") Platform index(" << in_device.platformIndex << ")" << std::endl;
            return false;
        }
        
        return true;
    }
    //-----------------------------------------------------------------------------
    inline void AppAllium::onRun(uint32_t first_nonce, size_t num_hashes)
    {
        if (num_hashes > m_maxWorkSize)
        {
            std::cout << "Warning: numHashes > maxHashesPerRun!" << std::endl;
            num_hashes = m_maxWorkSize;
        }

        cl_int errorCode = CL_SUCCESS;
        clSetKernelArg(m_clKernelBlake32, 12, sizeof(uint32_t), &first_nonce);

        const size_t globalWorkSize = num_hashes;
        const size_t globalWorkSize4x = num_hashes*4;
        const size_t localWorkSize = 256;
        const size_t lyraLocalWorkSize = 64;
        // blake32
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelBlake32, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
        // keccak-f1600
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelKeccakF1600, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
							   
        // // lyra2
        // clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra2, 1, nullptr,
                               // &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
                               
        // lyra441p1
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra441p1, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
        // lyra441p2
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra441p2, 1, nullptr,
                               &globalWorkSize4x, &lyraLocalWorkSize, 0, nullptr, nullptr);
        // lyra441p3
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra441p3, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
        // cubeHash256
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelCubeHash256, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
							   
        // // lyra2
        // clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra2, 1, nullptr,
                               // &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
							   
        // lyra441p1
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra441p1, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
        // lyra441p2
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra441p2, 1, nullptr,
                               &globalWorkSize4x, &lyraLocalWorkSize, 0, nullptr, nullptr);
        // lyra441p3
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelLyra441p3, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
        // skein
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelSkein, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
        // bmwHtarg
        // clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelBmwHtarg, 1, nullptr,
                               // &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
                               
        // groestl256Htarg
        clEnqueueNDRangeKernel(m_clCommandQueue, m_clKernelGroestl256Htarg, 1, nullptr,
                               &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);

        clFinish(m_clCommandQueue);
    }
    //-----------------------------------------------------------------------------
    inline void AppAllium::getHashes(std::vector<alliumHash>& lyra_hashes)
    {
        if(lyra_hashes.size() < m_maxWorkSize)
            lyra_hashes.resize(m_maxWorkSize);    
        clEnqueueReadBuffer(m_clCommandQueue, m_clMemHashStorage, CL_TRUE, 0, m_maxWorkSize * sizeof(alliumHash), lyra_hashes.data(), 0, nullptr, nullptr);
    }
    //-----------------------------------------------------------------------------
    //inline void AppAllium::clearResult()
    inline void AppAllium::clearResult(size_t num_elements)
    {
        // prepare clear buffer
        // opencl 1.2+
        cl_uint zero = 0;
        //int errorCode = clEnqueueFillBuffer(m_clCommandQueue, m_clMemHtArgResult, &zero, sizeof(uint32_t), 0, sizeof(uint32_t)*2, 0, nullptr, nullptr);
        // clear numElements+Elements...
        int errorCode = clEnqueueFillBuffer(m_clCommandQueue, m_clMemHtArgResult, &zero, sizeof(uint32_t), 0, (sizeof(uint32_t)*num_elements) + 1, 0, nullptr, nullptr);
        if(errorCode != CL_SUCCESS)
            std::cerr << "Failed to clear a hTarg buffer object!" << std::endl;

        // slower alternative
        //uint32_t bdata[2] = { 0 };
        //clEnqueueWriteBuffer(m_clCommandQueue, m_clMemHtArgResult, CL_TRUE, 0, sizeof(uint32_t)*2, &bdata[0], 0, nullptr, nullptr);
    }
    //-----------------------------------------------------------------------------
    inline void AppAllium::setKernelData(const KernelData& kernel_data)
    {
        clSetKernelArg(m_clKernelBlake32, 1, sizeof(uint32_t), &kernel_data.uH0);
        clSetKernelArg(m_clKernelBlake32, 2, sizeof(uint32_t), &kernel_data.uH1);
        clSetKernelArg(m_clKernelBlake32, 3, sizeof(uint32_t), &kernel_data.uH2);
        clSetKernelArg(m_clKernelBlake32, 4, sizeof(uint32_t), &kernel_data.uH3);
        clSetKernelArg(m_clKernelBlake32, 5, sizeof(uint32_t), &kernel_data.uH4);
        clSetKernelArg(m_clKernelBlake32, 6, sizeof(uint32_t), &kernel_data.uH5);
        clSetKernelArg(m_clKernelBlake32, 7, sizeof(uint32_t), &kernel_data.uH6);
        clSetKernelArg(m_clKernelBlake32, 8, sizeof(uint32_t), &kernel_data.uH7);
        clSetKernelArg(m_clKernelBlake32, 9, sizeof(uint32_t), &kernel_data.in16);
        clSetKernelArg(m_clKernelBlake32, 10, sizeof(uint32_t), &kernel_data.in17);
        clSetKernelArg(m_clKernelBlake32, 11, sizeof(uint32_t), &kernel_data.in18);
        // set htarg for groestl256HTarg kernel
        clSetKernelArg(m_clKernelGroestl256Htarg, 2, sizeof(cl_ulong), &kernel_data.htArg);
    }
    //-----------------------------------------------------------------------------
    inline void AppAllium::getHtArgTestResultAndSize(uint32_t &out_nonce, uint32_t &out_dbgCount)
    {
        uint32_t aResult[2];
        // assume only one nonce was found here
        clEnqueueReadBuffer(m_clCommandQueue, m_clMemHtArgResult, CL_TRUE, 0, 2 * sizeof(uint32_t), &aResult[0], 0, nullptr, nullptr);

        out_nonce = aResult[1];
        out_dbgCount = aResult[0];
    }
    //-----------------------------------------------------------------------------
    inline void AppAllium::getHtArgTestResults(std::vector<uint32_t>& out_htargs, size_t num_elements, size_t offset_elem)
    {
        if(out_htargs.size() < num_elements)
            out_htargs.resize(num_elements);    
        clEnqueueReadBuffer(m_clCommandQueue, m_clMemHtArgResult, CL_TRUE, offset_elem * sizeof(uint32_t), num_elements*sizeof(uint32_t), out_htargs.data(), 0, nullptr, nullptr);
    }
    //-----------------------------------------------------------------------------
    inline void AppAllium::getLatestHashResultForIndex(uint32_t index, alliumHash& out_hash)
    {
        clEnqueueReadBuffer(m_clCommandQueue, m_clMemHashStorage, CL_TRUE, (size_t)sizeof(alliumHash)*index, sizeof(alliumHash), &out_hash, 0, nullptr, nullptr);
    }
    //-----------------------------------------------------------------------------
    inline void AppAllium::onDestroy()
    {
        // memory objects
        clReleaseMemObject(m_clMemHashStorage);
        clReleaseMemObject(m_clMemLyraStates);
        clReleaseMemObject(m_clMemHtArgResult);
		// groestl256Htarg
        clReleaseKernel(m_clKernelGroestl256Htarg);
        clReleaseProgram(m_clProgramGroestl256Htarg);
        // skein
        clReleaseKernel(m_clKernelSkein);
        clReleaseProgram(m_clProgramSkein);
        // lyra441p3
        clReleaseKernel(m_clKernelLyra441p3);
        clReleaseProgram(m_clProgramLyra441p3);
        // lyra441p2
        clReleaseKernel(m_clKernelLyra441p2);
        clReleaseProgram(m_clProgramLyra441p2);
        // lyra441p1
        clReleaseKernel(m_clKernelLyra441p1);
        clReleaseProgram(m_clProgramLyra441p1);
        // // lyra2
        // clReleaseKernel(m_clKernelLyra2);
        // clReleaseProgram(m_clProgramLyra2);
        // cubeHash256
        clReleaseKernel(m_clKernelCubeHash256);
        clReleaseProgram(m_clProgramCubeHash256);
        // keccakF1600
        clReleaseKernel(m_clKernelKeccakF1600);
        clReleaseProgram(m_clProgramKeccakF1600);
        // blake32
        clReleaseKernel(m_clKernelBlake32);
        clReleaseProgram(m_clProgramBlake32);
        // misc
        clReleaseCommandQueue(m_clCommandQueue);
        clReleaseContext(m_clContext);
    }
    //-----------------------------------------------------------------------------
}

#endif // !AppAllium_INCLUDE_ONCE

