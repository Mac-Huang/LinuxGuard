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

/// Detects use-after-free vulnerabilities. Specifically, it detects code where a
/// memory block (e.g., 'new_pp') is freed and then immediately dereferenced on
/// the subsequent line, often after a conditional check that doesn't prevent
/// the use-after-free. This targets code patterns where a function call's
/// failure triggers both memory deallocation and subsequent use of the freed
/// memory.
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