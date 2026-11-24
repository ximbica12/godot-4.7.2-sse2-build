#!/usr/bin/env python3
"""Patch GDE GoZen for D3D11VA/DXVA2 decode with safe software fallback."""

from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one patch anchor, found {count}. Upstream source changed; stopping safely.")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_between(path: Path, start: str, end: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(start) != 1:
        raise SystemExit(f"{path}: expected one start anchor. Upstream source changed; stopping safely.")
    a = text.index(start)
    b = text.find(end, a + len(start))
    if b < 0:
        raise SystemExit(f"{path}: end anchor not found after start.")
    path.write_text(text[:a] + replacement + text[b:], encoding="utf-8")


def replace_once_in_block(path: Path, block_start: str, block_end: str, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(block_start) != 1:
        raise SystemExit(f"{path}: expected one function start anchor.")
    a = text.index(block_start)
    b = text.find(block_end, a + len(block_start))
    if b < 0:
        raise SystemExit(f"{path}: function end anchor not found.")
    block = text[a:b]
    count = block.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one patch anchor inside function, found {count}.")
    block = block.replace(old, new, 1)
    path.write_text(text[:a] + block + text[b:], encoding="utf-8")


if len(sys.argv) != 2:
    raise SystemExit("Usage: patch_gozen_hybrid.py PATH/TO/gde_gozen")

root = Path(sys.argv[1]).resolve()
build_py = root / "build.py"
sconstruct = root / "SConstruct"
ffmpeg_hpp = root / "src/ffmpeg.hpp"
ffmpeg_cpp = root / "src/ffmpeg.cpp"
video_hpp = root / "src/gozen_video.hpp"
video_cpp = root / "src/gozen_video.cpp"

# The upstream build explicitly disables hardware accelerators and x86 assembly.
replace_once(build_py, '    "--disable-hwaccels",\n', "")
replace_once_in_block(
    build_py,
    "def compile_ffmpeg_windows(arch: str) -> None:\\n",
    "\\ndef compile_ffmpeg_macos",
    '        "--disable-asm",\\n',
    '        "--enable-x86asm",\\n',
)
replace_once(
    build_py,
    '        "--enable-schannel",\n',
    '        "--enable-schannel",\n        "--enable-d3d11va",\n        "--enable-dxva2",\n',
)

# Link Windows system libraries used by FFmpeg's D3D11VA/DXVA2 backends.
replace_once(
    sconstruct,
    '        LIBS=["ws2_32", "bcrypt", "secur32", "shlwapi", "mfuuid", "strmiids"],\n',
    '        LIBS=["ws2_32", "bcrypt", "secur32", "shlwapi", "mfuuid", "strmiids", "d3d11", "dxgi", "dxva2", "ole32", "uuid"],\n',
)

# Correct FFmpeg's get_format callback signature.
replace_once(
    ffmpeg_hpp,
    '\\tstatic enum AVPixelFormat get_hw_format(AVCodecContext* codec_ctx, const enum AVPixelFormat* pix_fmts);\n',
    '    static enum AVPixelFormat get_hw_format(AVCodecContext* codec_ctx, const enum AVPixelFormat* pix_fmts);\n',
)
replace_between(
    ffmpeg_cpp,
    'enum AVPixelFormat FFmpeg::get_hw_format(',
    '\n}\n\n// For',
    r'''enum AVPixelFormat FFmpeg::get_hw_format(AVCodecContext* codec_ctx, const enum AVPixelFormat* pix_fmts) {
    if (!codec_ctx || !codec_ctx->opaque || !pix_fmts)
        return AV_PIX_FMT_NONE;

    const AVPixelFormat wanted = *static_cast<const AVPixelFormat*>(codec_ctx->opaque);
    for (const enum AVPixelFormat* p = pix_fmts; *p != AV_PIX_FMT_NONE; ++p) {
        if (*p == wanted)
            return *p;
    }

    return AV_PIX_FMT_NONE;''',
)

# Hardware state and CPU-readable staging frame. OpenGL remains the renderer.
replace_once(
    video_hpp,
    '\tUniqueAVFrame av_sws_frame;\n\tUniqueSwsCtx sws_ctx;\n',
    '\tUniqueAVFrame av_sws_frame;\n\tUniqueAVFrame av_hw_frame;\n\tUniqueSwsCtx sws_ctx;\n',
)
replace_once(
    video_hpp,
    '\tbool using_sws = false; // This is set for when the pixel format is foreign and not directly supported by the addon.\n',
    '\tbool using_sws = false; // This is set for when the pixel format is foreign and not directly supported by the addon.\n\tbool hardware_decode = false;\n\tAVPixelFormat hw_pix_fmt = AV_PIX_FMT_NONE;\n\tString hwaccel_name = "software";\n',
)
replace_once(
    video_hpp,
    '\tvoid _copy_frame_data();\n\tvoid _clean_frame_data();\n',
    '\tvoid _copy_frame_data();\n\tvoid _clean_frame_data();\n\tbool _open_codec(const AVCodec* codec, AVHWDeviceType device_type);\n\tbool _fallback_to_software(const AVCodec* codec);\n',
)
replace_once(
    video_hpp,
    '\tinline bool get_debug_enabled() const { return debug; }\n',
    '\tinline bool get_debug_enabled() const { return debug; }\n\tinline String get_hwaccel_name() const { return hwaccel_name; }\n',
)

# Add D3D11VA -> DXVA2 -> software decoder selection.
replace_once(
    video_cpp,
    '#include "gozen_video.hpp"\n\n\nint GoZenVideo::open(',
    r'''#include "gozen_video.hpp"


bool GoZenVideo::_open_codec(const AVCodec* codec, AVHWDeviceType device_type) {
    if (!codec || !av_stream)
        return false;

    av_codec_ctx.reset();
    hardware_decode = false;
    hw_pix_fmt = AV_PIX_FMT_NONE;
    hwaccel_name = "software";

    auto create_context = [&]() -> bool {
        av_codec_ctx = make_unique_ffmpeg<AVCodecContext, AVCodecCtxDeleter>(avcodec_alloc_context3(codec));
        if (!av_codec_ctx)
            return false;
        if (avcodec_parameters_to_context(av_codec_ctx.get(), av_stream->codecpar) < 0) {
            av_codec_ctx.reset();
            return false;
        }
        FFmpeg::enable_multithreading(av_codec_ctx.get(), codec);
        return true;
    };

    if (device_type == AV_HWDEVICE_TYPE_NONE) {
        if (!create_context())
            return false;
        if (avcodec_open2(av_codec_ctx.get(), codec, nullptr) < 0) {
            av_codec_ctx.reset();
            return false;
        }
        _log("Using FFmpeg software decoder");
        return true;
    }

    for (int i = 0;; ++i) {
        const AVCodecHWConfig* config = avcodec_get_hw_config(codec, i);
        if (!config)
            break;
        if (config->device_type != device_type ||
            !(config->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX))
            continue;

        AVBufferRef* device_ctx = nullptr;
        int result = av_hwdevice_ctx_create(&device_ctx, device_type, nullptr, nullptr, 0);
        if (result < 0 || !device_ctx) {
            if (device_ctx)
                av_buffer_unref(&device_ctx);
            continue;
        }

        if (!create_context()) {
            av_buffer_unref(&device_ctx);
            return false;
        }

        av_codec_ctx->hw_device_ctx = av_buffer_ref(device_ctx);
        av_buffer_unref(&device_ctx);
        if (!av_codec_ctx->hw_device_ctx) {
            av_codec_ctx.reset();
            continue;
        }

        hw_pix_fmt = config->pix_fmt;
        av_codec_ctx->opaque = &hw_pix_fmt;
        av_codec_ctx->get_format = &FFmpeg::get_hw_format;
        av_codec_ctx->thread_count = 1;
        av_codec_ctx->thread_type = 0;

        result = avcodec_open2(av_codec_ctx.get(), codec, nullptr);
        if (result == 0) {
            hardware_decode = true;
            const char* device_name = av_hwdevice_get_type_name(device_type);
            hwaccel_name = device_name ? String(device_name) : String("hardware");
            _log(String("Hardware video decoding active: ") + hwaccel_name);
            return true;
        }

        if (debug)
            FFmpeg::print_av_error("Hardware decoder initialization failed: ", result);
        av_codec_ctx.reset();
        hw_pix_fmt = AV_PIX_FMT_NONE;
    }

    return false;
}


bool GoZenVideo::_fallback_to_software(const AVCodec* codec) {
    if (!hardware_decode || !codec)
        return false;

    _log("Hardware decode failed; falling back to software");
    if (!_open_codec(codec, AV_HWDEVICE_TYPE_NONE))
        return false;

    const int64_t seek_timestamp = av_stream->start_time != AV_NOPTS_VALUE ? av_stream->start_time : 0;
    if (av_seek_frame(av_format_ctx.get(), av_stream->index, seek_timestamp, AVSEEK_FLAG_BACKWARD) < 0)
        return false;

    avformat_flush(av_format_ctx.get());
    avcodec_flush_buffers(av_codec_ctx.get());
    if (av_frame)
        av_frame_unref(av_frame.get());
    if (av_packet)
        av_packet_unref(av_packet.get());
    if (av_hw_frame)
        av_frame_unref(av_hw_frame.get());

    return true;
}


int GoZenVideo::open(''',
)

replace_between(
    video_cpp,
    '\t// Allocate codec context for decoder.\n',
    '\t// Adjust resolution according to the aspect ratio.\n',
    r'''    bool codec_opened = _open_codec(av_codec, AV_HWDEVICE_TYPE_D3D11VA);
    if (!codec_opened)
        codec_opened = _open_codec(av_codec, AV_HWDEVICE_TYPE_DXVA2);
    if (!codec_opened)
        codec_opened = _open_codec(av_codec, AV_HWDEVICE_TYPE_NONE);
    if (!codec_opened) {
        close();
        return _log_err("Couldn't open codec");
    }

''',
)

replace_once(
    video_cpp,
    '\tav_frame = make_unique_avframe();\n\tav_sws_frame = make_unique_avframe();\n\n\tif (!av_packet || !av_frame || !av_sws_frame) {\n',
    '\tav_frame = make_unique_avframe();\n\tav_sws_frame = make_unique_avframe();\n\tav_hw_frame = make_unique_avframe();\n\n\tif (!av_packet || !av_frame || !av_sws_frame || !av_hw_frame) {\n',
)

# If hardware initialization or first-frame transfer fails, rewind and reopen in software.
replace_between(
    video_cpp,
    '\twhile (true) {\n\t\tresponse = FFmpeg::get_frame(av_format_ctx.get(), av_codec_ctx.get(), av_stream->index, av_frame.get(),\n',
    '\n\t// Checking for interlacing and what type of interlacing.\n',
    r'''    while (true) {
        response = FFmpeg::get_frame(av_format_ctx.get(), av_codec_ctx.get(), av_stream->index, av_frame.get(),
                                     av_packet.get());

        if (response == 0) {
            if (hardware_decode) {
                av_frame_unref(av_hw_frame.get());
                response = av_hwframe_transfer_data(av_hw_frame.get(), av_frame.get(), 0);
                if (response < 0) {
                    FFmpeg::print_av_error("Hardware frame transfer failed: ", response);
                    if (_fallback_to_software(av_codec))
                        continue;
                    close();
                    return _log_err("Failed to transfer hardware video frame");
                }
            }
            break;
        } else if (response == AVERROR(EAGAIN) || response == AVERROR(EWOULDBLOCK)) {
            if (attempts > 10) {
                if (_fallback_to_software(av_codec)) {
                    attempts = 0;
                    continue;
                }
                FFmpeg::print_av_error("Reached max attempts trying to get first frame! ", response);
                close();
                return _log_err("Failed to decode first frame (max attempts)");
            }
            attempts++;
        } else {
            if (_fallback_to_software(av_codec)) {
                attempts = 0;
                continue;
            }
            if (response == AVERROR_EOF)
                FFmpeg::print_av_error("Reached EOF trying to get first frame! ", response);
            else
                FFmpeg::print_av_error("Something went wrong getting first frame! ", response);
            close();
            return _log_err("Failed to decode first frame");
        }
    }
''',
)

replace_once(
    video_cpp,
    '\t// Checking for interlacing and what type of interlacing.\n\tif (av_frame->flags & AV_FRAME_FLAG_INTERLACED)\n\t\tinterlaced = av_frame->flags & AV_FRAME_FLAG_TOP_FIELD_FIRST ? 1 : 2;\n\n\t// Checking color range.\n\tfull_color_range = av_frame->color_range == AVCOL_RANGE_JPEG;\n',
    '\tAVFrame* source_frame = hardware_decode ? av_hw_frame.get() : av_frame.get();\n\n\t// Checking for interlacing and what type of interlacing.\n\tif (source_frame->flags & AV_FRAME_FLAG_INTERLACED)\n\t\tinterlaced = source_frame->flags & AV_FRAME_FLAG_TOP_FIELD_FIRST ? 1 : 2;\n\n\t// Checking color range.\n\tfull_color_range = source_frame->color_range == AVCOL_RANGE_JPEG;\n',
)

replace_between(
    video_cpp,
    '\t// Check for alpha layer.\n',
    '\n\tduration = av_format_ctx->duration;',
    r'''    const AVPixFmtDescriptor* desc = av_pix_fmt_desc_get((AVPixelFormat)source_frame->format);
    has_alpha = desc && (desc->flags & AV_PIX_FMT_FLAG_ALPHA);
    if (source_frame->format == AV_PIX_FMT_PAL8)
        has_alpha = true;

    pixel_format = av_get_pix_fmt_name((AVPixelFormat)source_frame->format);
    _log(String("Selected pixel format is: ") + pixel_format);

    int uv_width = (actual_resolution.x + 1) / 2;
    int uv_height = (actual_resolution.y + 1) / 2;
    bool is_natively_supported = (source_frame->format == AV_PIX_FMT_YUV420P ||
                                  source_frame->format == AV_PIX_FMT_YUVJ420P ||
                                  source_frame->format == AV_PIX_FMT_YUVA420P);

    if (is_natively_supported) {
        padding = source_frame->linesize[0] - actual_resolution.x;
        y_data = Image::create_empty(actual_resolution.x, actual_resolution.y, false, Image::FORMAT_R8);
        u_data = Image::create_empty(uv_width, uv_height, false, Image::FORMAT_R8);
        v_data = Image::create_empty(uv_width, uv_height, false, Image::FORMAT_R8);

        if (has_alpha)
            a_data = Image::create_empty(actual_resolution.x, actual_resolution.y, false, Image::FORMAT_R8);
    } else {
        AVPixelFormat new_format = has_alpha ? AV_PIX_FMT_YUVA420P : AV_PIX_FMT_YUV420P;

        using_sws = true;
        sws_ctx = make_unique_ffmpeg<SwsContext, SwsCtxDeleter>(
            sws_getContext(actual_resolution.x, actual_resolution.y, (AVPixelFormat)source_frame->format,
                           actual_resolution.x, actual_resolution.y, new_format, sws_flag, nullptr, nullptr, nullptr));

        if (!sws_ctx) {
            close();
            return _log_err("Failed to create pixel format conversion context");
        }

        sws_scale_frame(sws_ctx.get(), av_sws_frame.get(), source_frame);

        padding = av_sws_frame->linesize[0] - actual_resolution.x;
        y_data = Image::create_empty(actual_resolution.x, actual_resolution.y, false, Image::FORMAT_R8);
        u_data = Image::create_empty(uv_width, uv_height, false, Image::FORMAT_R8);
        v_data = Image::create_empty(uv_width, uv_height, false, Image::FORMAT_R8);

        if (has_alpha)
            a_data = Image::create_empty(actual_resolution.x, actual_resolution.y, false, Image::FORMAT_R8);

        av_frame_unref(av_sws_frame.get());
    }
''',
)

replace_once(
    video_cpp,
    '\tif (av_frame)\n\t\tav_frame_unref(av_frame.get());\n\n\tloaded = true;\n',
    '\tif (av_frame)\n\t\tav_frame_unref(av_frame.get());\n\tif (av_hw_frame)\n\t\tav_frame_unref(av_hw_frame.get());\n\n\tloaded = true;\n',
)

replace_between(
    video_cpp,
    'void GoZenVideo::_copy_frame_data() {\n',
    '\nint GoZenVideo::_seek_frame(int frame_nr) {',
    r'''void GoZenVideo::_copy_frame_data() {
    if (!av_frame || av_frame->data[0] == nullptr) {
        _log("Frame is empty");
        return;
    }

    AVFrame* source_frame = av_frame.get();
    if (hardware_decode) {
        av_frame_unref(av_hw_frame.get());
        int transfer_result = av_hwframe_transfer_data(av_hw_frame.get(), av_frame.get(), 0);
        if (transfer_result < 0) {
            FFmpeg::print_av_error("Could not transfer hardware frame to system memory: ", transfer_result);
            return;
        }
        source_frame = av_hw_frame.get();
    }

    int uv_width = (actual_resolution.x + 1) / 2;
    int uv_height = (actual_resolution.y + 1) / 2;

    if (using_sws) {
        sws_scale_frame(sws_ctx.get(), av_sws_frame.get(), source_frame);

        for (int i = 0; i < actual_resolution.y; i++) {
            memcpy(y_data->ptrw() + i * actual_resolution.x, av_sws_frame->data[0] + i * av_sws_frame->linesize[0],
                   actual_resolution.x);
        }
        for (int i = 0; i < uv_height; i++) {
            memcpy(u_data->ptrw() + i * uv_width, av_sws_frame->data[1] + i * av_sws_frame->linesize[1], uv_width);
            memcpy(v_data->ptrw() + i * uv_width, av_sws_frame->data[2] + i * av_sws_frame->linesize[2], uv_width);
        }

        if (has_alpha) {
            for (int i = 0; i < actual_resolution.y; i++) {
                memcpy(a_data->ptrw() + i * actual_resolution.x, av_sws_frame->data[3] + i * av_sws_frame->linesize[3],
                       actual_resolution.x);
            }
        }

        av_frame_unref(av_sws_frame.get());
    } else {
        for (int i = 0; i < actual_resolution.y; i++) {
            memcpy(y_data->ptrw() + i * actual_resolution.x, source_frame->data[0] + i * source_frame->linesize[0],
                   actual_resolution.x);
        }
        for (int i = 0; i < uv_height; i++) {
            memcpy(u_data->ptrw() + i * uv_width, source_frame->data[1] + i * source_frame->linesize[1], uv_width);
            memcpy(v_data->ptrw() + i * uv_width, source_frame->data[2] + i * source_frame->linesize[2], uv_width);
        }

        if (has_alpha) {
            for (int i = 0; i < actual_resolution.y; i++) {
                memcpy(a_data->ptrw() + i * actual_resolution.x, source_frame->data[3] + i * source_frame->linesize[3],
                       actual_resolution.x);
            }
        }
    }

    if (hardware_decode)
        av_frame_unref(av_hw_frame.get());
}
''',
)

replace_once(
    video_cpp,
    '\tav_sws_frame.reset();\n\tsws_ctx.reset();\n',
    '\tav_sws_frame.reset();\n\tav_hw_frame.reset();\n\tsws_ctx.reset();\n\thardware_decode = false;\n\thw_pix_fmt = AV_PIX_FMT_NONE;\n\thwaccel_name = "software";\n',
)
replace_once(
    video_cpp,
    '\tBIND_METHOD(get_debug_enabled);\n',
    '\tBIND_METHOD(get_debug_enabled);\n\tBIND_METHOD(get_hwaccel_name);\n',
)

print("GoZen patched: D3D11VA -> DXVA2 -> FFmpeg software fallback; OpenGL rendering is unchanged.")
