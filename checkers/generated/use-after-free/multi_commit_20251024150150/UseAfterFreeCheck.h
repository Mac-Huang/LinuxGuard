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

/// Checks Linux kernel code for use-after-free vulnerabilities. This check
/// detects situations where a resource is freed and subsequently accessed,
/// potentially due to race conditions or incorrect handling of resource lifetimes.
/// Vulnerable code patterns include using delayed work items, workqueues, or
/// asynchronicity, freeing a resource before all references are gone, and a
/// missing or incorrect check.
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