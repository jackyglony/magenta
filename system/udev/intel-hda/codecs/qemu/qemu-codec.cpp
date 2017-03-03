// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <intel-hda-driver-utils/client-thread.h>
#include <intel-hda-driver-utils/debug-logging.h>
#include <magenta/new.h>
#include <mxtl/auto_lock.h>

#include "qemu-codec.h"
#include "qemu-stream.h"

class QemuInputStream : public QemuStream  {
public:
    static constexpr uint32_t STREAM_ID = 2;
    static constexpr uint16_t CONVERTER_NID = 4;
    QemuInputStream() : QemuStream(STREAM_ID, true, CONVERTER_NID) { }
};

class QemuOutputStream : public QemuStream  {
public:
    static constexpr uint32_t STREAM_ID = 1;
    static constexpr uint16_t CONVERTER_NID = 2;
    QemuOutputStream() : QemuStream(STREAM_ID, false, CONVERTER_NID) { }
};

void QemuCodec::PrintDebugPrefix() const {
    printf("QEMUCodec : ");
}

mxtl::RefPtr<QemuCodec> QemuCodec::Create() {
    AllocChecker ac;

    auto codec = mxtl::AdoptRef(new (&ac) QemuCodec);
    if (!ac.check())
        return nullptr;

    return codec;
}

mx_status_t QemuCodec::Init(mx_driver_t* driver, mx_device_t* codec_dev) {
    mx_status_t res = Bind(driver, codec_dev);
    if (res != NO_ERROR)
        return res;

    res = Start();
    if (res != NO_ERROR) {
        Shutdown();
        return res;
    }

    return NO_ERROR;
}

mx_status_t QemuCodec::Start() {
    mx_status_t res;

    AllocChecker ac;
    auto output = mxtl::AdoptRef<QemuStream>(new (&ac) QemuOutputStream());
    if (!ac.check()) {
        LOG("Failed to allocate memory for output stream!");
        return ERR_NO_MEMORY;
    }

    auto input = mxtl::AdoptRef<QemuStream>(new (&ac) QemuInputStream());
    if (!ac.check()) {
        LOG("Failed to allocate memory for input stream!");
        return ERR_NO_MEMORY;
    }

    res = ActivateStream(output);
    if (res != NO_ERROR) {
        LOG("Failed to activate output stream (res %d)!", res);
        return res;
    }

    res = ActivateStream(input);
    if (res != NO_ERROR) {
        LOG("Failed to activate input stream (res %d)!", res);
        return res;
    }

    return NO_ERROR;
}

extern "C" mx_status_t qemu_ihda_codec_bind_hook(mx_driver_t* driver,
                                                 mx_device_t* codec_dev,
                                                 void** cookie) {
    if (cookie == nullptr)
        return ERR_INVALID_ARGS;

    auto codec = QemuCodec::Create();
    if (codec == nullptr)
        return ERR_NO_MEMORY;

    // Init our codec.  If we succeed, transfer our reference to the unmanaged
    // world.  We will re-claim it later when unbind is called.
    mx_status_t res = codec->Init(driver, codec_dev);
    if (res == NO_ERROR)
        *cookie = codec.leak_ref();

    return res;
}

extern "C" void qemu_ihda_codec_unbind_hook(mx_driver_t* driver,
                                            mx_device_t* codec_dev,
                                            void* cookie) {
    DEBUG_ASSERT(cookie != nullptr);

    // Reclaim our reference from the cookie.
    auto codec = mxtl::internal::MakeRefPtrNoAdopt(reinterpret_cast<QemuCodec*>(cookie));

    // Shut the codec down.
    codec->Shutdown();

    // Let go of the reference.
    codec.reset();

    // Signal the thread pool so it can completely shut down if we were the last client.
    ClientThread::ShutdownThreadPool();
}

