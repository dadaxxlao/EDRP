#!/bin/bash

# 设置默认值
BUILD_DIR="builddir"
BUILD_TYPE="debug"
LOG_LEVEL="debug"
CLEAN=false
RECONFIGURE=false

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo "选项:"
    echo "  -h, --help            显示帮助信息"
    echo "  -b, --build-dir DIR   设置构建目录 (默认: builddir)"
    echo "  -t, --type TYPE       设置构建类型 (debug/release, 默认: debug)"
    echo "  -l, --log-level LEVEL 设置日志级别 (debug/info/warn/error, 默认: debug)"
    echo "  -c, --clean           清理构建目录"
    echo "  -r, --reconfigure     重新配置meson"
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -b|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -t|--type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -r|--reconfigure)
            RECONFIGURE=true
            shift
            ;;
        *)
            echo "错误: 未知选项 $1"
            show_help
            exit 1
            ;;
    esac
done

# 清理构建目录
if [ "$CLEAN" = true ]; then
    echo "清理构建目录 $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
fi

# 创建构建目录
mkdir -p "$BUILD_DIR"

# 配置meson
if [ ! -f "$BUILD_DIR/build.ninja" ] || [ "$RECONFIGURE" = true ]; then
    echo "配置meson..."
    meson setup "$BUILD_DIR" \
        --buildtype="$BUILD_TYPE" \
        -Dlog_level="$LOG_LEVEL" \
        || exit 1
fi

# 运行ninja编译
echo "开始编译..."
ninja -C "$BUILD_DIR" || exit 1

echo "构建完成！"
