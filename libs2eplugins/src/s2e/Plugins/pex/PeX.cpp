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

#include <llvm/ADT/DenseSet.h>
//#include <bfd.h>
#include <cstdio>
#include "PeX.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(PeX, "PeX S2E plugin", "", );

void PeX::initialize() {
    auto *config = s2e()->getConfig();
    m_traceBlockTranslation = config->getBool(getConfigKey() + ".traceBlockTranslation");
    m_traceBlockExecution = config->getBool(getConfigKey() + ".traceBlockExecution");
    m_killWhenNotInRange = config->getBool(getConfigKey() + ".killWhenNotInRange");
    processPCRange();
    processTargetStackInfo();
    auto *plugin = s2e()->getCorePlugin();
    // hook bb start
    plugin->onTranslateBlockStart.connect(sigc::mem_fun(*this, &PeX::slotTranslateBlockStart));
    plugin->onPortAccess.connect(sigc::mem_fun(*this, &PeX::slotOnPortAccess));
    // hook bb end to capture call/jump
    // plugin->onTranslateBlockEnd.connect(
    //        sigc::mem_fun(*this, &PeX::slotTranslateBlockEnd));
    /*
     * monitor all instruction execution
     */
    // plugin->onTranslateInstructionStart.connect(
    //        sigc::mem_fun(*this, &PeX::onTranslateInstructionStart));
    /*
     * monitor all memory access
     */
    // plugin->onConcreteDataMemoryAccess.connect(
    //        sigc::mem_fun(*this, &PeX::onConcreteDataMemoryAccess));
    os_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
}

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

void PeX::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                     unsigned flags) {
    uint64_t pc = state->regs()->getPc();
    if (!os_monitor->isKernelAddress(pc))
        return;
    getDebugStream(state) << "PC:" << hexval(pc) << " access " << hexval(size) << " bytes of "
                          << "memory (flag " << hexval(flags) << ")"
                          << " @ " << hexval(address) << " content=" << hexval(value) << "\n";
    // make accessed memory symbolic
    // makesymbolic(state,address,value,size,flags);
}

#if 0
int PeX::makesymbolic(lua_state *l) {
    long address = (long) lual_checkinteger(l, 1);
    long size = (long) lual_checkinteger(l, 2);
    std::string name = lual_checkstring(l, 3);

    std::vector<uint8_t> concretedata(size);
    if (!m_state->mem()->read(address, concretedata.data(), size * sizeof(uint8_t))) {
        lua_pushinteger(l, 0);
        return 1;
    }

    std::vector<klee::ref<klee::expr>> symb = m_state->createsymbolicarray(name, size, concretedata);

    for (unsigned i = 0; i < size; ++i) {
        if (!m_state->mem()->write(address + i, symb[i])) {
            lua_pushinteger(l, 0);
            return 1;
        }
    }

    lua_pushinteger(l, 1);
    return 1;
}
#endif
void PeX::slotOnPortAccess(S2EExecutionState *state, klee::ref<klee::Expr> port, klee::ref<klee::Expr> value,
                           bool isWrite) {
#if 1
    std::string rw;
    uint64_t cport, cvalue;
    cport = dyn_cast<klee::ConstantExpr>(port.get())->getZExtValue();
    cvalue = dyn_cast<klee::ConstantExpr>(value.get())->getZExtValue();
    if (cport != 0xcf8)
        return;
    if (isWrite)
        rw = "write";
    else
        rw = "reaad";
    getDebugStream(state) << rw << "  port " << hexval(cport) << " value=" << hexval(cvalue) << "\n";
#endif
}

} // namespace plugins
} // namespace s2e
