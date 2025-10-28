//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_LINUXKERNEL_USEAFTERFREECHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_LINUXKERNEL_USEAFTERFREECHECK_H

#include "../ClangTidyCheck.h"

namespace clang::tidy::linuxkernel {

/// Detects use-after-free vulnerabilities in Linux kernel code. Specifically,
/// it checks for a pattern where the `ocelot_stats_deinit` function attempts to
/// cancel a delayed work item (`ocelot->stats_work`) using
/// `cancel_delayed_work()`.  If the work item is already executing,
/// `cancel_delayed_work()` might fail, and the work queue is destroyed
/// before the delayed work is completed. If the timer associated with the
/// `stats_work` expires after the workqueue is destroyed, the delayed work
/// item will be scheduled on the now-invalid work queue, resulting in a
/// use-after-free.
///
/// For the user-facing documentation see:
/// https://clang.llvm.org/extra/clang-tidy/checks/linuxkernel/use-after-free.html
class UseAfterFreeCheck : public ClangTidyCheck {
public:
  UseAfterFreeCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace clang::tidy::linuxkernel

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_LINUXKERNEL_USEAFTERFREECHECK_H