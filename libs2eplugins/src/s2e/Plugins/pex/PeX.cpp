/*
 * PeX S2E Plugin
 * 2020 Tong Zhang <ztong0001@gmail.com>
 */
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include <s2e/SymbolicHardwareHook.h>

#include <cstdio>
#include <llvm/ADT/DenseSet.h>
#include "PeX.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(PeX, "PeX S2E plugin", "", );

#include "pexcb.h"

void PeX::initialize() {
    os_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    // configs specified by user
    auto *config = s2e()->getConfig();
    // m_traceBlockTranslation = config->getBool(getConfigKey() + ".traceBlockTranslation");
    // m_traceBlockExecution = config->getBool(getConfigKey() + ".traceBlockExecution");
    // m_killWhenNotInRange = config->getBool(getConfigKey() + ".killWhenNotInRange");
    m_delay_enable_symbhw = config->getInt(getConfigKey() + ".delayEnableSymbHW");
    m_printAllPortAccess = config->getBool(getConfigKey() + ".printAllPortAccess");
    reg_vid = config->getInt(getConfigKey() + ".VID");
    reg_pid = config->getInt(getConfigKey() + ".PID");
#if 0
    // processPCRange();
    // processTargetStackInfo();
#endif
    auto *plugin = s2e()->getCorePlugin();
    // PORT access hook
    plugin->onPortAccess.connect(sigc::mem_fun(*this, &PeX::slotOnPortAccess));
    // MMIO hook
    g_symbolicPortHook = SymbolicPortHook(_isPortSymbolic, symbolicPortRead, symolicPortWrite, this);
    g_symbolicMemoryHook = SymbolicMemoryHook(_isMmioSymbolic, symbolicMMIORead, symbolicMMIOWrite, this);

#if 0
    // hook bb start
    plugin->onTranslateBlockStart.connect(sigc::mem_fun(*this, &PeX::slotTranslateBlockStart));
    // hook bb end to capture call/jump
     plugin->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &PeX::slotTranslateBlockEnd));
    /*
     * monitor all instruction execution
     */
    plugin->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &PeX::onTranslateInstructionStart));
    /*
     * monitor all memory access
     */
    plugin->slotOnConcreteDataMemoryAccess.connect(sigc::mem_fun(*this, &PeX::slotOnConcreteDataMemoryAccess));
#endif
}

// called after g_s2e_state is available
void PeX::pluginInit2(S2EExecutionState *state) {
    // set initial PCI config data
    auto &pci_header = state->mem()->sfpPCIDeviceHeader;
    // bar registers
#if 1
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR0] = BAR_INIT_VALUE;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR1] = BAR_INIT_VALUE;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR2] = BAR_INIT_VALUE;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR3] = BAR_INIT_VALUE;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR4] = BAR_INIT_VALUE;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR5] = BAR_INIT_VALUE;
#else
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR0] = 0xffffffff;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR1] = 0xffffffff;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR2] = 0xffffffff;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR3] = 0xffffffff;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR4] = 0xffffffff;
    pci_header.reg[PCI_CONFIG_DATA_REG_BAR5] = 0xffffffff;
#endif
    // status and command
    pci_header.reg[PCI_CONFIG_DATA_REG_1] = 0x0000000;
    // Class code/Subclass
    pci_header.reg[PCI_CONFIG_DATA_REG_2] = 0x2000000;
    // header type need to be zero
    pci_header.reg[PCI_CONFIG_DATA_REG_3] = 0;
    // card bus ptr
    pci_header.reg[PCI_CONFIG_DATA_REG_A] = 0xffffffff;
    // Subsystem ID, Subsystem Vendor ID
    pci_header.reg[PCI_CONFIG_DATA_REG_B] = 0xffffffff;
    // expansion rom
    pci_header.reg[PCI_CONFIG_DATA_REG_C] = 0xffffffff;
    // Reserved	Capabilities Pointer
    pci_header.reg[PCI_CONFIG_DATA_REG_D] = 0xffffffff;
    // Reserved
    pci_header.reg[PCI_CONFIG_DATA_REG_E] = 0xffffffff;
    // interrupt
    pci_header.reg[PCI_CONFIG_DATA_REG_F] = 1;
    // setup VID and PIC
    pci_header.reg[PCI_CONFIG_DATA_REG_0] = (reg_pid << 16) | reg_vid;
}

//////////////////////////////////////////////////////////////////////////
bool PeX::isPortSymbolic(S2EExecutionState *state, uint16_t port) {
    static int count = m_delay_enable_symbhw;
    if (count != 0) {
        count--;
        if (count == 0)
            getDebugStream(state) << " PeX ... start Symbolic HW on port PCI_CONFIG*\n";
        return false;
    }
    switch (port) {
        case PCI_CONFIG_ADDRESS_PORT ... PCI_CONFIG_DATA_PORT_END:
            return true;
        default:
            break;
    }
    // port falls into bar mapped to IO address space
    if (fallsIntoBar(state, port)) {
        getDebugStream(state) << " PeX ... port access to mapped bar, port " << hexval(port) << "\n";
        return true;
    }
    return false;
}

bool PeX::isMmioSymbolic(S2EExecutionState *state, uint64_t physAddr) {
    if (fallsIntoBar(state, physAddr)) {
        getDebugStream(state) << " - MMIO @ " << hexval(physAddr) << "\n";
        return true;
    }
    return false;
}

void PeX::slotOnConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                         unsigned flags) {
#if 0
//this is not working
  int baridx = -1;
  for (int i = 0; i < 6; i++) {
      auto barl = bar[i];
      auto barh = barl + ~BAR_HMASK;
      if ((address >= barl) && (address <= barh)) {
          baridx = i;
          getDebugStream(state) << " Accessing Bar " << baridx << " address = " << hexval(address) << "\n";
          break;
      }
  }
#endif
}

bool PeX::isOurDevice() {
    // FIXME: is g_s2e_state the current state?
    uint32_t reg_pci_cfg_addr = getPortIORegister(PCI_CONFIG_ADDRESS_PORT);
    uint8_t bus = BUS_ADDR(reg_pci_cfg_addr);
    uint8_t device = DEV_ADDR(reg_pci_cfg_addr);
    if ((bus == SYMDEV_BUS) && (device == SYMDEV_DEV)) {
        return true;
    }
    return false;
}

bool PeX::fallsIntoBar(S2EExecutionState *state, uint64_t physAddr) {
    auto &pci_header = getPCIHeader(state);
    uint32_t *bar = &(pci_header.reg[PCI_CONFIG_DATA_REG_BAR0]);
    // getDebugStream(g_s2e_state) << " MMIO @ " << hexval(physAddr) << "\n";
    for (int i = 0; i < 6; i++) {
        if ((bar[i] == 0xffffffff) || (bar[i] == 0) || (bar[i] == BAR_INIT_VALUE))
            continue;
        auto barlo = (uint64_t)(bar[i]) & 0xFFFFFFF0;
        auto barhi = (uint64_t)(barlo + ~BAR_HMASK) & 0xFFFFFFF0;
        if ((physAddr >= barlo) && (physAddr <= barhi))
            return true;
    }
    return false;
}

void PeX::dumpbar(S2EExecutionState *state) {
    auto &pci_header = getPCIHeader(state);
    uint32_t *bar = &(pci_header.reg[PCI_CONFIG_DATA_REG_BAR0]);
    for (int i = 0; i < 6; i++) {
        if ((bar[i] == 0xffffffff) || (bar[i] == 0) || (bar[i] == BAR_INIT_VALUE))
            continue;
        auto barlo = bar[i] & 0xFFFFFFF0;
        auto barhi = (barlo + ~BAR_HMASK) + 0xFFFFFFF0;
        getDebugStream(state) << " PeX ... BAR " << i << " [" << hexval(barlo) << " - " << hexval(barhi) << "]\n";
    }
}

void PeX::writeBAR(S2EExecutionState *state, uint32_t reg, uint32_t value) {
    if (!isOurDevice())
        return;
    auto &pci_header = getPCIHeader(state);
    if (value == 0xffffffff) {
        pci_header.reg[reg] = BAR_HMASK | 0x01;
    } else {
        pci_header.reg[reg] = value | 0x01;
        dumpbar(state);
    }
    auto baridx = reg - PCI_CONFIG_DATA_REG_BAR0;
    getDebugStream(state) << " PeX ... write BAR[" << baridx << "] = " << hexval(value) << "\n";
}

void PeX::slotOnPortAccess(S2EExecutionState *state, KleeExprRef port, KleeExprRef value, bool isWrite) {
#if 1
    auto &pci_header = getPCIHeader(state);
    uint64_t cport = 0, cvalue = 0;
    if (auto *_cport = dyn_cast<klee::ConstantExpr>(port.get())) {
        cport = _cport->getZExtValue();
    }
    if (auto *_cvalue = dyn_cast<klee::ConstantExpr>(value.get())) {
        cvalue = _cvalue->getZExtValue();
    } else {
        if (isWrite) {
            getDebugStream(state) << "write sym value to port\n";
        }
    }
    if (isWrite) {
        switch (cport) {
            case PCI_CONFIG_ADDRESS_PORT: {
                uint32_t reg_pci_cfg_addr = (uint32_t) cvalue;
                setPortIORegister(PCI_CONFIG_ADDRESS_PORT, reg_pci_cfg_addr);
                uint8_t bus = BUS_ADDR(reg_pci_cfg_addr);
                uint8_t device = DEV_ADDR(reg_pci_cfg_addr);
                uint8_t function = FUN_ADDR(reg_pci_cfg_addr);
                uint8_t reg = REG_ADDR(reg_pci_cfg_addr);
                getDebugStream(state) << " PeX ... set PCI_CONFIG_ADDRESS : " << value << " Bus " << hexval(bus)
                                      << ", Dev " << hexval(device) << ", Func " << hexval(function) << ", Reg "
                                      << hexval(reg) << "\n";
                break;
            }
            case PCI_CONFIG_DATA_PORT ... PCI_CONFIG_DATA_PORT_END: {
                uint32_t reg_pci_cfg_addr = getPortIORegister(PCI_CONFIG_ADDRESS_PORT);
                auto regaddr = REG_ADDR(reg_pci_cfg_addr);
                if ((regaddr >= PCI_CONFIG_DATA_REG_BAR0) && (regaddr <= PCI_CONFIG_DATA_REG_BAR5)) {
                    writeBAR(state, regaddr, cvalue);
                } else {
                    // other registers ----
                    pci_header.reg[regaddr] = cvalue;
                }
                break;
            }
            default:
                break;
        }
    } else {
        // port read
        if ((cport >= PCI_CONFIG_DATA_PORT) && (cport <= PCI_CONFIG_DATA_PORT_END)) {
            uint32_t reg_pci_cfg_addr = getPortIORegister(PCI_CONFIG_ADDRESS_PORT);
            uint8_t bus = BUS_ADDR(reg_pci_cfg_addr);
            uint8_t device = DEV_ADDR(reg_pci_cfg_addr);
            uint8_t function = FUN_ADDR(reg_pci_cfg_addr);
            uint8_t reg = REG_ADDR(reg_pci_cfg_addr);
            getDebugStream(state) << " PeX ... get PCI_CONFIG_DATA_PORT from : " << hexval(reg_pci_cfg_addr)
                                  << " BDFR = " << hexval(bus) << "," << hexval(device) << "," << hexval(function)
                                  << "," << hexval(reg) << "   value = " << hexval(cvalue) << "\n";
            switch (reg) {
                case 0: {
                    getDebugStream(state) << " PeX ... "
                                          << "@BDFR:" << hexval(bus) << "," << hexval(device) << "," << hexval(function)
                                          << "," << hexval(reg) << " feeding VID:PID = " << hexval(cvalue) << "\n";
                    break;
                }
                case PCI_CONFIG_DATA_REG_BAR0 ... PCI_CONFIG_DATA_REG_BAR5: {
                    getDebugStream(state) << " PeX ... reading BAR " << (reg - 4) << " @ : " << hexval(cvalue) << "\n";
                    break;
                }
                default:
                    break;
            }
        }
    }
    if (m_printAllPortAccess) {
        std::string rw = isWrite ? "write" : "read";
        getDebugStream(state) << rw << "  port " << port << " value=" << value << "\n";
    }
#endif
}
#if 1
template <typename T> static void SymbHwGetConcolicVector(T in, unsigned size, ConcreteArray &out) {
    union {
        // XXX: assumes little endianness!
        T value;
        uint8_t array[8];
    };
    value = in;
    out.resize(size);
    for (unsigned i = 0; i < size; ++i) {
        out[i] = array[i];
    }
}
#endif
KleeExprRef PeX::createExpressionPort(S2EExecutionState *state, uint64_t address, unsigned size,
                                      uint64_t concreteValue) {
    auto &pci_header = getPCIHeader(state);
    auto cfc_offset = address - 0xcfc;

    uint32_t reg_pci_cfg_addr = getPortIORegister(PCI_CONFIG_ADDRESS_PORT);
    // auto function = FUN_ADDR(reg_pci_cfg_addr);
    std::stringstream ss;
    ss << "PCI device @ " << hexval(reg_pci_cfg_addr) << " portread ";
    uint8_t reg = REG_ADDR(reg_pci_cfg_addr);
    ss << hexval(address) << " size " << size << " @" << hexval(state->regs()->getPc());

    if (!isOurDevice())
        goto end;
    if ((address < PCI_CONFIG_DATA_PORT) || (address > PCI_CONFIG_DATA_PORT_END))
        goto end;
    if (fallsIntoBar(state, address))
        goto symend;

    switch (reg) {
        case PCI_CONFIG_DATA_REG_0:
        case PCI_CONFIG_DATA_REG_2 ... PCI_CONFIG_DATA_REG_3:
        case PCI_CONFIG_DATA_REG_A:
        case PCI_CONFIG_DATA_REG_B:
        case PCI_CONFIG_DATA_REG_C:
        case PCI_CONFIG_DATA_REG_D:
        case PCI_CONFIG_DATA_REG_E: {
            ss << " sym=no\n";
            getDebugStream(g_s2e_state) << ss.str();
            goto concend;
        }

#if 0
        case PCI_CONFIG_DATA_REG_BAR0: {
            ss << " sym=yes";
            goto symend;
        }
#endif
        case PCI_CONFIG_DATA_REG_BAR0 ... PCI_CONFIG_DATA_REG_BAR5: {
            auto idx = reg - PCI_CONFIG_DATA_REG_BAR0;
            ss << " access bar @ " << idx << " sym=no \n";
            getDebugStream(g_s2e_state) << ss.str();
#if 0
            // the last bit of bar indicates whether this is IO or MEM, thus we need to mark it symbolic
            // https://en.wikipedia.org/wiki/PCI_configuration_space#cite_note-8
            ConcreteArray concolicValue;
            SymbHwGetConcolicVector(pci_header.reg[reg], size, concolicValue);
            getDebugStream(g_s2e_state) << ss.str();
            return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
#else
            // create LEGACY IO region
            return klee::ExtractExpr::create(klee::ConstantExpr::create(pci_header.reg[reg], 64), 0, size * 8);
#endif
        }
        case PCI_CONFIG_DATA_REG_1:
        case PCI_CONFIG_DATA_REG_F:
        default: {
            ss << " sym=yes\n";
            goto symend;
        }
    }
symend : {
#if 0
    ConcreteArray concolicValue;
    if (size == 1) {
        SymbHwGetConcolicVector(getPCIReg8(reg, cfc_offset), size, concolicValue);
    } else if (size == 2) {
        SymbHwGetConcolicVector(getPCIReg16(reg, cfc_offset), size, concolicValue);
    } else {
        SymbHwGetConcolicVector(getPCIReg32(reg), size, concolicValue);
    }
    return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
#else
    return state->createSymbolicValue(ss.str(), size * 8);
#endif
}
concend : {
    if (size == 1) {
        return klee::ExtractExpr::create(klee::ConstantExpr::create(getPCIReg8(state, reg, cfc_offset), 8), 0,
                                         size * 8);
    } else if (size == 2) {
        return klee::ExtractExpr::create(klee::ConstantExpr::create(getPCIReg16(state, reg, cfc_offset), 16), 0,
                                         size * 8);
    } else {
        return klee::ExtractExpr::create(klee::ConstantExpr::create(getPCIReg32(state, reg), 32), 0, size * 8);
    }
}
end : { return klee::ExtractExpr::create(klee::ConstantExpr::create(concreteValue, 64), 0, size * 8); }
}

KleeExprRef PeX::createExpressionMMIO(S2EExecutionState *state, uint64_t address, unsigned size,
                                      uint64_t concreteValue) {
    std::stringstream ss;
    ss << "BAR MMIO @ ";
    ss << hexval(address) << " size " << size << " pc=" << hexval(state->regs()->getPc());
    return state->createSymbolicValue(ss.str(), size * 8);
}

// dmesg from m_logBuf and m_logBufLen
// std::string str;
// state->mem()->readString(m_logBuf, str, m_log_bufLen);

/////////////////////////////////////////////////////////////////////////
// dust
#if 0
void PeX::processTargetStackInfo() {
    auto *config = s2e()->getConfig();
    auto pcrangeFilePath = config->getString(getConfigKey() + ".pcrange");
    std::ifstream file(pcrangeFilePath);
    if (!file.is_open())
        return;
    std::string line;
    while (std::getline(file, line)) {
        if (line == "---stack binary range---")
            break;
    }
    while (std::getline(file, line)) {
        if (line == "EOR") {
            // end of range
            break;
        }
        uint64_t pc1, pc2;
        int found = line.find("[");
        std::string str = line.substr(found + 1);
        std::sscanf(str.c_str(), "0x%lx,0x%lx", &pc1, &pc2);
        pcrange_pair p;
        if (pc1 > pc2)
            p = std::make_pair(pc1, pc2);
        else
            p = std::make_pair(pc2, pc2);
        targetStack.push_back(p);
    }
    file.close();
}

void PeX::processPCRange() {
    auto *config = s2e()->getConfig();
    auto pcrangeFilePath = config->getString(getConfigKey() + ".pcrange");
    std::ifstream file(pcrangeFilePath);
    if (!file.is_open())
        return;
    std::string line;
    while (std::getline(file, line)) {
        if (line == "---possible pc range---")
            break;
    }
    while (std::getline(file, line)) {
        if (line == "EOR") {
            // end of range
            break;
        }
        uint64_t pc1, pc2;
        int found = line.find("[");
        std::string str = line.substr(found + 1);
        std::sscanf(str.c_str(), "0x%lx,0x%lx", &pc1, &pc2);
        pcrange_pair p;
        if (pc1 > pc2)
            p = std::make_pair(pc1, pc2);
        else
            p = std::make_pair(pc2, pc2);
        pcrange.push_back(p);
    }
    file.close();
}
void PeX::slotTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                  uint64_t pc) {
    if (!os_monitor->isKernelAddress(pc))
        return;
    if (m_traceBlockTranslation) {
        // getDebugStream(state) <<"kernel Start
        // @"<<hexval(os_monitor->getKernelStart())<<"\n";
        getDebugStream(state) << "Translating kernel block at " << hexval(pc) << "\n";
        // getDebugStream(state) << "Translating kernel block @ " <<
        // hexval(pc-os_monitor->getKernelStart()) << "\n";
    }

    if (m_traceBlockExecution) {
        signal->connect(sigc::mem_fun(*this, &PeX::slotExecuteBlockStart));
    }
}

bool PeX::isInRange(uint64_t pc) {
    for (const auto &p : pcrange) {
        // high
        if (p.first < pc)
            continue;
        // low
        if (p.second > pc)
            continue;
        return true;
    }
    return false;
}

bool PeX::isDestRange(uint64_t pc) {
    if (pcrange.size() == 0)
        return false;
    auto &p = pcrange.front();
    // high
    if (p.first < pc)
        return false;
    // low
    if (p.second > pc)
        return false;
    return true;
}

bool PeX::isTargetStack(std::vector<uint64_t> &stack) {
    int depth = targetStack.size();
    if (stack.size() < depth)
        return false;
    for (int i = 0; i < depth; i++) {
        auto pair = targetStack[i];
        auto highpc = pair.first;
        auto lowpc = pair.second;
        auto pc = stack[i];
        if (pc < lowpc)
            return false;
        if (pc > highpc)
            return false;
    }
    return true;
}

#define PAGE_SIZE 0x1000
#define PAGE_MASK ~(0x0fff)
#define STACK_MAX_SIZE (PAGE_SIZE * 2)

std::vector<uint64_t> PeX::unwindStack(S2EExecutionState *state) {
    std::vector<uint64_t> stack;
    // read out stack
    auto pc = state->regs()->getPc();
    stack.push_back(pc);
    auto sp = state->regs()->getSp();
    auto bp = state->regs()->getBp();
    auto stacklow = sp & PAGE_MASK;
    auto stackhigh = sp + STACK_MAX_SIZE;
    getDebugStream(state) << " stack pointer sp=" << hexval(sp) << " stack low = " << hexval(stacklow)
                          << " stack high = " << hexval(stackhigh) << "\n"
                          << " base pointer[stack frame] bp=" << hexval(bp) << "\n";
    uint8_t stackSnapshot[STACK_MAX_SIZE];
    state->mem()->read(stacklow, stackSnapshot, STACK_MAX_SIZE);
    uint64_t *stackPtr = (uint64_t *) stackSnapshot;
    auto ptrSize = sizeof(uint64_t);
    auto ptrCnt = STACK_MAX_SIZE / ptrSize;
#if 0
  getDebugStream(state)<<" ===== STACK ==== \n";
  for (int i=0;i<ptrCnt;i++) {
    getDebugStream(state)<<"   ["
     <<i<<"] => " << hexval(stacklow + i*ptrSize) <<" = "
     <<hexval(stackPtr[i])<<"\n";
  }
#endif
    // this is where we start
    int bpOffset = (bp - stacklow) / ptrSize;
    if (bpOffset < 0 || bpOffset >= ptrCnt) { // there's an error
        getDebugStream(state) << " error unwinding stack\n";
        goto end;
    }
    while (bpOffset < ptrCnt) {
        auto retOffset = bpOffset + 1;
        if (retOffset < 0 || retOffset >= ptrCnt) {
            // getDebugStream(state)<<" doesn't look like a valid stack here\n";
            break;
        }
        stack.push_back(stackPtr[retOffset]);
        auto nextBp = stackPtr[bpOffset];
        auto nextBpOffset = (nextBp - stacklow) / ptrSize;
        if (nextBpOffset <= bpOffset) {
            // getDebugStream(state)<<" doesn't look like a valid stack here\n";
            break;
        }
        bpOffset = nextBpOffset;
    }
end:
    return stack;
}

void PeX::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    if (!os_monitor->isKernelAddress(pc)) {
        return;
    }
    if (m_traceBlockExecution) {
        auto *e = s2e()->getExecutor();
        auto count = e->getStatesCount();
        if (count <= 1)
            return;
        if (isDestRange(pc)) {
            auto stack = unwindStack(state);
            ////////////////
            getDebugStream(state) << " === to match stack ===\n";
            for (auto pc : stack)
                getDebugStream(state) << "  " << hexval(pc) << "\n";
            ///////////////

            if (isTargetStack(stack)) {
                getDebugStream(state) << "Target Stack Identified\n";
            }
        }
        if ((m_killWhenNotInRange) && (!isInRange(pc))) {
            getDebugStream(state) << "terminating state " << count << " pc @ " << hexval(pc) << "\n";
            e->terminateState(*state);
        }
        // jump to itself
        // jumpToPc(state, exeTrace[cnt]);
    }
}

void PeX::jumpToPc(S2EExecutionState *state, uint64_t pc) {
    state->regs()->setPc(pc);
    throw CpuExitException();
}

void PeX::slotTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                bool staticTarget, uint64_t targetPc) {
    if (!os_monitor->initialized()) {
        return;
    }
    if (!os_monitor->isKernelAddress(pc)) {
        return;
    }

    if (tb->se_tb_type == TB_CALL) {
        signal->connect(sigc::mem_fun(*this, &PeX::onExecuteDirectCall));
    }
    if (tb->se_tb_type == TB_CALL_IND) {
        signal->connect(sigc::mem_fun(*this, &PeX::onExecuteIndirectCall));
    }
}

void PeX::onExecuteIndirectCall(S2EExecutionState *state, uint64_t pc) {
    auto calleepc = state->regs()->getPc();
    getDebugStream(state) << " execute indirect call @ " << hexval(pc) << " callee pc:" << hexval(calleepc) << "\n";
    // guide indirect execution here
    if (pc2pc.find(pc) != pc2pc.end())
        jumpToPc(state, pc2pc[pc]);
}

void PeX::onExecuteDirectCall(S2EExecutionState *state, uint64_t pc) {
    auto calleepc = state->regs()->getPc();
    getDebugStream(state) << " execute direct call @ " << hexval(pc) << " callee pc:" << hexval(calleepc) << "\n";
}

void PeX::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                      uint64_t pc) {
    if (!os_monitor->isKernelAddress(pc))
        return;
    signal->connect(sigc::mem_fun(*this, &PeX::onInstruction));
}

void PeX::onInstruction(S2EExecutionState *state, uint64_t pc) {
}
#endif

} // namespace plugins
} // namespace s2e
