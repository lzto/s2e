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

#include <llvm/ADT/DenseSet.h>
//#include <bfd.h>
#include <cstdio>
#include "PeX.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(PeX, "PeX S2E plugin", "", );

void PeX::initialize() {
  auto* config = s2e()->getConfig();
  m_traceBlockTranslation =
      config->getBool(getConfigKey() + ".traceBlockTranslation");
  m_traceBlockExecution =
      config->getBool(getConfigKey() + ".traceBlockExecution");
  processPCRange();

  auto* plugin = s2e()->getCorePlugin();
  // hook bb start
  plugin->onTranslateBlockStart.connect(
      sigc::mem_fun(*this, &PeX::slotTranslateBlockStart));
  // hook bb end to capture call/jump
  //plugin->onTranslateBlockEnd.connect(
  //        sigc::mem_fun(*this, &PeX::slotTranslateBlockEnd));
  /*
   * monitor all instruction execution
   */
  //plugin->onTranslateInstructionStart.connect(
  //        sigc::mem_fun(*this, &PeX::onTranslateInstructionStart));
  /*
   * monitor all memory access
   */
  //plugin->onConcreteDataMemoryAccess.connect(
  //        sigc::mem_fun(*this, &PeX::onConcreteDataMemoryAccess));
  m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
}
void PeX::processPCRange() {
  auto* config = s2e()->getConfig();
  auto pcrangeFilePath = config->getString(getConfigKey() +".pcrange");
  std::ifstream file(pcrangeFilePath);
  if (!file.is_open())
    return;
  std::string line;
  while (std::getline(file, line)) {
    if (line=="---possible pc range---")
      break;
  }
  while (std::getline(file, line)) {
    uint64_t pc1, pc2;
    int found = line.find("[");
    std::string str = line.substr(found+1);
    std::sscanf(str.c_str(), "0x%lx,0x%lx",&pc1,&pc2);
    pcrange_pair p;
    if (pc1>pc2)
      p = std::make_pair(pc1, pc2);
    else
      p = std::make_pair(pc2, pc2);
    pcrange.push_back(p);
  }
  file.close();
}

void PeX::slotTranslateBlockStart(ExecutionSignal *signal,
                                  S2EExecutionState *state,
                                  TranslationBlock *tb, uint64_t pc) {
  if (!m_monitor->isKernelAddress(pc))
    return;
  if (m_traceBlockTranslation) {
    // getDebugStream(state) <<"kernel Start
    // @"<<hexval(m_monitor->getKernelStart())<<"\n";
    getDebugStream(state) << "Translating kernel block at " << hexval(pc)
                          << "\n";
    // getDebugStream(state) << "Translating kernel block @ " <<
    // hexval(pc-m_monitor->getKernelStart()) << "\n";
  }

  if (m_traceBlockExecution) {
    signal->connect(sigc::mem_fun(*this, &PeX::slotExecuteBlockStart));
  }
}

bool PeX::isInRange(uint64_t pc) {
    for (const auto &p: pcrange) {
      //high 
      if (p.first < pc)
        continue;
      //low
      if (p.second > pc)
        continue;
      return true;
    }
    return false;
}

bool PeX::isDestRange(uint64_t pc) {
  if (pcrange.size()==0)
      return false;
  auto &p = pcrange.front();
  //high 
  if (p.first < pc)
      return false;
  //low
  if (p.second > pc)
      return false;
  return true;
}

void PeX::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
  if (!m_monitor->isKernelAddress(pc)) {
    return;
  }
  if (m_traceBlockExecution)
  {
    auto* e = s2e()->getExecutor();
    auto count = e->getStatesCount();
    if (count<=1)
      return;
    if (isDestRange(pc)) {
      getDebugStream(state)<<"DestRange Reached "<<count<<" pc @ "
          <<hexval(pc)<<"\n";
    }
    if (!isInRange(pc)) {
      getDebugStream(state)<<"terminating state "<<count<<" pc @ "
          <<hexval(pc)<<"\n";
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

void PeX::slotTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
        TranslationBlock *tb, uint64_t pc, bool staticTarget,
        uint64_t targetPc) {
    if (!m_monitor->initialized()) {
        return;
    }
    if (!m_monitor->isKernelAddress(pc)) {
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
  getDebugStream(state) <<" execute indirect call @ "<<hexval(pc)
      <<" callee pc:"<<hexval(calleepc)<<"\n";
  // guide indirect execution here
  if (pc2pc.find(pc)!=pc2pc.end())
    jumpToPc(state, pc2pc[pc]);
}

void PeX::onExecuteDirectCall(S2EExecutionState *state, uint64_t pc) {
  auto calleepc = state->regs()->getPc();
  getDebugStream(state) <<" execute direct call @ "<<hexval(pc)
      <<" callee pc:"<<hexval(calleepc)<<"\n";
}

void PeX::onTranslateInstructionStart(ExecutionSignal *signal,
          S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
  if (!m_monitor->isKernelAddress(pc))
    return;
  signal->connect(sigc::mem_fun(*this, &PeX::onInstruction));
}

void PeX::onInstruction(S2EExecutionState *state, uint64_t pc) {
}

void PeX::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address,
        uint64_t value, uint8_t size, unsigned flags) {
  uint64_t pc = state->regs()->getPc();
  if (!m_monitor->isKernelAddress(pc))
    return;
  getDebugStream(state) << "PC:"<<hexval(pc)<<" access "
      << hexval(size) <<" bytes of "
      <<"memory (flag "<<hexval(flags)<<")"
      <<" @ "<<hexval(address) 
      <<" content="<<hexval(value)<<"\n";
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
} // namespace plugins
} // namespace s2e
