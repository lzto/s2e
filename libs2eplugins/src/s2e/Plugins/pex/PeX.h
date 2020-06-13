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
#include <list>
namespace s2e {
namespace plugins {

class OSMonitor;

class PeX : public Plugin {
  S2E_PLUGIN
public:
  PeX(S2E *s2e) : Plugin(s2e) {}
  ~PeX() {
  }

  void initialize();

  void slotTranslateBlockStart(ExecutionSignal *, S2EExecutionState *state,
                               TranslationBlock *tb, uint64_t pc);
  void slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

  void slotTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
          TranslationBlock *tb, uint64_t pc,
          bool staticTarget, uint64_t targetPc);
  void onExecuteDirectCall(S2EExecutionState *state, uint64_t pc);
  void onExecuteIndirectCall(S2EExecutionState *state, uint64_t pc);
  void onTranslateInstructionStart(ExecutionSignal *signal,
          S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
  void onInstruction(S2EExecutionState *state, uint64_t pc);
  void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t vaddr,
          uint64_t value, uint8_t size, unsigned flags);

protected:

private:
  OSMonitor *m_monitor;
  bool m_traceBlockTranslation;
  bool m_traceBlockExecution;
  void processPCRange();
  bool isInRange(uint64_t);
  bool isDestRange(uint64_t);
  typedef std::pair<uint64_t,uint64_t> pcrange_pair;
  typedef std::list<pcrange_pair> PCRange;
  PCRange pcrange;

  std::map<uint64_t, uint64_t> pc2pc;
  void jumpToPc(S2EExecutionState *state, uint64_t pc);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_PEX_H
