// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_MAGLEV_TYPE_CONFUSION_TRACING_H_
#define V8_MAGLEV_MAGLEV_TYPE_CONFUSION_TRACING_H_

#include "src/base/macros.h"
#include "src/base/platform/platform.h"
#include "src/flags/flags.h"
#include "src/utils/ostreams.h"

// Instrumentation for offline / LLM-assisted analysis of Maglev type-confusion
// bugs. Every statement below is gated on --trace-maglev-type-confusion and is
// a no-op unless that developer flag is passed, so it has zero cost in normal
// runs. These are observational logs only: they never change compiler
// behaviour.
//
// Each line has the form:
//   [MGLV-TC][t=<ms>ms][<channel>] <file>:<line> <function>: <message>
// where:
//   * <ms>       is base::OS::TimeCurrentMillis() at the log point (wall-clock
//                milliseconds), so events can be ordered/correlated over time;
//   * <channel>  is a short tag (e.g. "map", "nodetype", "repr", "elements")
//                so the output can be grepped per subsystem;
//   * <file>:<line> is the exact source location of the log statement;
//   * <function> is the fully-qualified function (via __PRETTY_FUNCTION__),
//                which includes the enclosing class/namespace when there is one;
//   * <message>  is streamed to StdoutStream via operator<<, so any V8 type
//                with an ostream operator (maps, node types, nodes, ...) works.
//
// Usage:
//   TRACE_TC("map", "CheckMaps on " << node << " maps=" << maps);

namespace v8 {
namespace internal {
namespace maglev {

#define TRACE_TC(channel, ...)                                     \
  do {                                                             \
    if (V8_UNLIKELY(v8_flags.trace_maglev_type_confusion)) {       \
      StdoutStream{} << "[MGLV-TC][t=" << base::OS::TimeCurrentMillis()    \
                     << "ms][" << (channel) << "] " << __FILE__            \
                     << ":" << __LINE__ << " " << __PRETTY_FUNCTION__      \
                     << ": " << __VA_ARGS__ << std::endl;                  \
    }                                                              \
  } while (false)

}  // namespace maglev
}  // namespace internal
}  // namespace v8

#endif  // V8_MAGLEV_MAGLEV_TYPE_CONFUSION_TRACING_H_
