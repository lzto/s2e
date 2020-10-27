/*
 * PeX S2E Plugin
 * 2020 Tong Zhang <ztong0001@gmail.com>
 */
#ifndef S2E_PLUGINS_PEX_H
#define S2E_PLUGINS_PEX_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/S2EExecutionState.h>
#include <utility>
#include <vector>

#include "commondef.h"
#include "pcidef.h"

// we want a fixed address in the PCI system
#define SYMDEV_BUS 0x00
#define SYMDEV_DEV 0x1b

namespace s2e {
namespace plugins {
class OSMonitor;

class PeX : public Plugin {
    S2E_PLUGIN
public:
    PeX(S2E *s2e) : Plugin(s2e) {
    }
    ~PeX() {
    }

    void initialize();
    void pluginInit2(S2EExecutionState *);

    void slotOnPortAccess(S2EExecutionState *, KleeExprRef port, KleeExprRef value, bool isWrite);
    void slotOnConcreteDataMemoryAccess(S2EExecutionState *, uint64_t vaddr, uint64_t value, uint8_t size,
                                        unsigned flags);
    bool isPortSymbolic(S2EExecutionState *, uint16_t port);
    bool isMmioSymbolic(S2EExecutionState *, uint64_t physAddr);
    // IO address space
    KleeExprRef createExpressionPort(S2EExecutionState *, uint64_t address, unsigned size, uint64_t concreteValue);
    // memory address space
    KleeExprRef createExpressionMMIO(S2EExecutionState *, uint64_t address, unsigned size, uint64_t concreteValue);

#if 0
    void slotTranslateBlockStart(ExecutionSignal *, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void slotTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                               bool staticTarget, uint64_t targetPc);
    void slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc);
    void onExecuteDirectCall(S2EExecutionState *state, uint64_t pc);
    void onExecuteIndirectCall(S2EExecutionState *state, uint64_t pc);
    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc);
    void onInstruction(S2EExecutionState *state, uint64_t pc);
#endif

private:
    OSMonitor *os_monitor;
    int m_delay_enable_symbhw;
    bool m_printAllPortAccess;
    // bool m_traceBlockTranslation;
    // bool m_traceBlockExecution;
    // bool m_killWhenNotInRange;

    uint32_t reg_vid;
    uint32_t reg_pid;

    // PCI specific
    void writeBAR(S2EExecutionState *, uint32_t reg, uint32_t value);
    bool fallsIntoBar(S2EExecutionState *, uint64_t phy_addr);
    void dumpbar(S2EExecutionState *);
    uint32_t getPortIORegister(uint32_t addr) {
        uint32_t ret;
        memcpy(&ret, &(g_s2e_state->mem()->portIOMem[addr]), sizeof(uint32_t));
        return ret;
    }
    void setPortIORegister(uint32_t addr, uint32_t val) {
        memcpy(&(g_s2e_state->mem()->portIOMem[addr]), &val, sizeof(uint32_t));
    }
    bool isOurDevice();

    // offset 0~3 - the byte offset
    uint8_t getPCIReg8(S2EExecutionState *s, int regidx, int offset) {
        auto &pci_header = s->mem()->sfpPCIDeviceHeader;
        uint8_t reg[4];
        memcpy(reg, &pci_header.reg[regidx], sizeof(uint32_t));
        return reg[offset];
    }
    // offset 0~3 - the byte offset -- yes it is byte offset
    uint16_t getPCIReg16(S2EExecutionState *s, int regidx, int offset) {
        auto &pci_header = s->mem()->sfpPCIDeviceHeader;
        uint16_t reg[2];
        memcpy(reg, &pci_header.reg[regidx], sizeof(uint32_t));
        return reg[offset >> 1];
    }
    uint32_t getPCIReg32(S2EExecutionState *s, int regidx) {
        auto &pci_header = s->mem()->sfpPCIDeviceHeader;
        return pci_header.reg[regidx];
    }

    PCI_HEADER &getPCIHeader(S2EExecutionState *state) {
        if (state)
            return state->mem()->sfpPCIDeviceHeader;
        return g_s2e_state->mem()->sfpPCIDeviceHeader;
    }

#if 0
    void processPCRange();
    void processTargetStackInfo();
    bool isInRange(uint64_t);
    bool isDestRange(uint64_t);
    bool isTargetStack(std::vector<uint64_t> &);
    typedef std::pair<uint64_t, uint64_t> pcrange_pair;
    typedef std::vector<pcrange_pair> PCRange;
    PCRange pcrange, targetStack;
    std::map<uint64_t, uint64_t> pc2pc;
    void jumpToPc(S2EExecutionState *state, uint64_t pc);
    std::vector<uint64_t> unwindStack(S2EExecutionState *state);
#endif
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_PEX_H
