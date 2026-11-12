// SLEIGH 的 C ABI 桥；地址映射与函数发现由托管侧提供，不依赖 Ghidra UI。
#include <ghidra/loadimage.hh>
#include <ghidra/context.hh>
#include <ghidra/sleigh.hh>
#include <ghidra/xml.hh>
#include <ghidra/marshal.hh>
#include <ghidra/architecture.hh>
#include <ghidra/globalcontext.hh>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#  define CPP2CS_API extern "C" __declspec(dllexport)
#else
#  define CPP2CS_API extern "C" __attribute__((visibility("default")))
#endif

// 桥 ABI 独立版本化，不暴露 Ghidra 的内部 C++ 对象布局。
struct Cpp2csVarnode {
  int32_t space_type;
  uint32_t size;
  uint64_t offset;
  const char* space_name;
  const char* register_name;
  const char* referenced_space;
};

using EmitCallback = void (*)(void* user, int32_t opcode, const char* opcode_name,
                              const Cpp2csVarnode* output,
                              const Cpp2csVarnode* inputs, int32_t input_count, const char* userop_name);

namespace {
void report(char* error, int32_t capacity, const std::string& message) noexcept {
  if (!error || capacity <= 0) return;
  std::snprintf(error, static_cast<size_t>(capacity), "%s", message.c_str());
  error[capacity - 1] = '\0';
}

std::string escapeXml(const char* raw) {
  std::string out;
  for (const char* p = raw; p && *p; ++p) {
    switch (*p) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      default: out += *p; break;
    }
  }
  return out;
}

class WindowImage final : public ghidra::LoadImage {
  const uint8_t* data_ = nullptr;
  int32_t count_ = 0;
  uint64_t start_ = 0;
public:
  WindowImage() : LoadImage("cpp2cs-x64-memory") {}
  void set(uint64_t start, const uint8_t* bytes, int32_t count) {
    start_ = start;
    data_ = bytes;
    count_ = count;
  }
  void loadFill(ghidra::uint1* dst, ghidra::int4 count,
                const ghidra::Address& at) override {
    // 允许推测性预读零填充；实际指令消耗长度必须在提供的字节范围内。
    for (ghidra::int4 i = 0; i < count; ++i) {
      uint64_t offset = at.getOffset() + static_cast<uint64_t>(i);
      dst[i] = offset >= start_ && offset - start_ < static_cast<uint64_t>(count_)
          ? data_[static_cast<size_t>(offset - start_)] : 0;
    }
  }
  std::string getArchType() const override { return "cpp2cs-x64"; }
  void adjustVma(long) override {}
};

class NativeBridge {
public:
  WindowImage image;
  ghidra::ContextInternal context;
  ghidra::Sleigh translator;
  ghidra::DocumentStorage documents;
  std::vector<std::string> userops;

  NativeBridge(const char* sla, const char* pspec)
      : translator(&image, &context) {
    if (!sla || !*sla) throw std::invalid_argument("Missing x86-64.sla path");
    // 以 sleigh 标签交给 Ghidra 12.2 加载编译后的规格。
    std::istringstream specification("<sleigh>" + escapeXml(sla) + "</sleigh>");
    ghidra::Element* root = documents.parseDocument(specification)->getRoot();
    documents.registerTag(root);
    if (pspec && *pspec) {
      ghidra::Element* p = documents.openDocument(pspec)->getRoot();
      documents.registerTag(p);
    }
    translator.initialize(documents);
    translator.getUserOpNames(userops);
    translator.allowContextSet(false);
    if (pspec && *pspec) {
      const ghidra::Element* p = documents.getTag("processor_spec");
      if (!p) throw std::runtime_error("Processor specification missing processor_spec tag");
      ghidra::XmlDecode decoder(&translator, p);
      const ghidra::uint4 id = decoder.openElement(ghidra::ELEM_PROCESSOR_SPEC);
      for (;;) {
        const ghidra::uint4 sub = decoder.peekElement();
        if (sub == 0) break;
        if (sub == ghidra::ELEM_CONTEXT_DATA) {
          context.decodeFromSpec(decoder);
          break;
        }
        decoder.openElement();
        decoder.closeElementSkipping(sub);
      }
      decoder.closeElement(id);
    }
    if (translator.getDefaultSize() != 8)
      throw std::runtime_error("Wrong SLEIGH language: expected 64-bit address space");
    context.setVariableDefault("addrsize", 2);
    context.setVariableDefault("opsize", 1);
    context.setVariableDefault("rexprefix", 0);
    context.setVariableDefault("longMode", 1);
  }
};

class Collector final : public ghidra::PcodeEmit {
  ghidra::Sleigh& translator_;
  EmitCallback emit_;
  void* user_;
  const std::vector<std::string>& userops_;

public:
  Collector(ghidra::Sleigh& t, EmitCallback emit, void* user, const std::vector<std::string>& userops)
      : translator_(t), emit_(emit), user_(user), userops_(userops) {}

  void dump(const ghidra::Address&, ghidra::OpCode opcode,
            ghidra::VarnodeData* output, ghidra::VarnodeData* vars,
            ghidra::int4 count) override {
    auto convert = [&](const ghidra::VarnodeData& v, std::string& regName) -> Cpp2csVarnode {
      regName = translator_.getRegisterName(v.space, v.offset, v.size);
      return {static_cast<int32_t>(v.space->getType()), static_cast<uint32_t>(v.size),
              static_cast<uint64_t>(v.offset), v.space->getName().c_str(), regName.c_str(), nullptr};
    };
    // getName 返回稳定字符串引用；同步回调期间这些指针有效。
    std::string outReg;
    Cpp2csVarnode out{};
    if (output) out = convert(*output, outReg);
    std::vector<std::string> names(static_cast<size_t>(count));
    std::vector<Cpp2csVarnode> inputs(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i)
      inputs[static_cast<size_t>(i)] = convert(vars[i], names[static_cast<size_t>(i)]);
    if ((opcode == ghidra::CPUI_LOAD || opcode == ghidra::CPUI_STORE) && count > 0) {
      const auto* space = vars[0].getSpaceFromConst();
      inputs[0].referenced_space = space->getName().c_str();
      inputs[0].offset = space->getIndex();
    }
    emit_(user_, static_cast<int32_t>(opcode), ghidra::get_opname(opcode),
          output ? &out : nullptr, inputs.data(), count,
          opcode == ghidra::CPUI_CALLOTHER && count > 0 && vars[0].offset < userops_.size()
              ? userops_[static_cast<size_t>(vars[0].offset)].c_str() : nullptr);
  }
};

class AssemblyCollector final : public ghidra::AssemblyEmit {
public:
  std::string mnemonic;
  void dump(const ghidra::Address&, const std::string& name, const std::string&) override { mnemonic = name; }
};

std::once_flag initOnce;
// Ghidra 的解析与上下文管理含共享状态；原生边界串行，托管恢复仍可并行。
std::mutex nativeMutex;
} // 匿名命名空间

CPP2CS_API int32_t cpp2cs_sleigh_abi_version() noexcept { return 3; }

CPP2CS_API void* cpp2cs_sleigh_open(const char* sla, const char* pspec,
                                    char* error, int32_t errorCapacity) noexcept {
  try {
    std::lock_guard<std::mutex> lock(nativeMutex);
    std::call_once(initOnce, [] {
      ghidra::AttributeId::initialize();
      ghidra::ElementId::initialize();
    });
    return new NativeBridge(sla, pspec);
  } catch (const ghidra::LowlevelError& ex) {
    report(error, errorCapacity, ex.explain);
  } catch (const std::exception& ex) {
    report(error, errorCapacity, ex.what());
  } catch (...) {
    report(error, errorCapacity, "Unknown SLEIGH initialization failure");
  }
  return nullptr;
}

CPP2CS_API int32_t cpp2cs_sleigh_instruction(void* handle, uint64_t address,
                                             const uint8_t* bytes, int32_t count,
                                             EmitCallback emit, void* user,
                                             char* mnemonic, int32_t mnemonicCapacity,
                                             char* error, int32_t errorCapacity) noexcept {
  if (!handle || !bytes || count <= 0 || count > 15 || !emit) {
    report(error, errorCapacity, "Bad SLEIGH arguments: expected 1..15 instruction bytes");
    return -1;
  }
  try {
    std::lock_guard<std::mutex> lock(nativeMutex);
    auto& bridge = *static_cast<NativeBridge*>(handle);
    // 调用方可以在同一地址提供不同字节，不能复用旧的反汇编缓存。
    bridge.translator.reset(&bridge.image, &bridge.context);
    bridge.translator.initialize(bridge.documents);
    bridge.translator.allowContextSet(false);
    bridge.image.set(address, bytes, count);
    Collector collector(bridge.translator, emit, user, bridge.userops);
    const ghidra::Address pc(bridge.translator.getDefaultCodeSpace(), address);
    AssemblyCollector assembly;
    bridge.translator.printAssembly(assembly, pc);
    report(mnemonic, mnemonicCapacity, assembly.mnemonic);
    const int32_t length = bridge.translator.oneInstruction(collector, pc);
    if (length <= 0 || length > count) {
      report(error, errorCapacity, "Decoded instruction extends beyond supplied mapped bytes");
      return -1;
    }
    return length;
  } catch (const ghidra::LowlevelError& ex) {
    report(error, errorCapacity, ex.explain);
  } catch (const std::exception& ex) {
    report(error, errorCapacity, ex.what());
  } catch (...) {
    report(error, errorCapacity, "Unknown SLEIGH instruction failure");
  }
  return -1;
}

CPP2CS_API void cpp2cs_sleigh_close(void* handle) noexcept {
  std::lock_guard<std::mutex> lock(nativeMutex);
  delete static_cast<NativeBridge*>(handle);
}
