//
// Created by Giovanni Arriciati on 07/06/26.
//

#ifndef GIARRI_ENCRYPT_LOGGING_H
#define GIARRI_ENCRYPT_LOGGING_H
#define LOG(msg) \
    std::clog << __FILE_NAME__ << "(" << __LINE__ << "): " << msg << std::endl;
#define LOG_ERR(msg) \
    std::cerr << "ERROR\t" << __FILE_NAME__ << "(" << __LINE__ << "): " << msg << std::endl;
#endif //GIARRI_ENCRYPT_LOGGING_H
