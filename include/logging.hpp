//
// Created by Giovanni Arriciati on 07/06/26.
//
#pragma once

#ifndef __FILE_NAME__
    #define __FILE_NAME__ __FILE__
#endif


#define LOG(msg) \
    std::clog << __FILE_NAME__ << "(" << __LINE__ << "): " << msg << std::endl;
#define LOG_ERR(msg) \
    std::cerr << "ERROR\t" << __FILE_NAME__ << "(" << __LINE__ << "): " << msg << std::endl;
