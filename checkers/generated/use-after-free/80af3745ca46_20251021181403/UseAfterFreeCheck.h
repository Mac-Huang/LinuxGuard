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

/// Detects use-after-free vulnerabilities. Specifically, it identifies cases where
/// memory is freed (e.g., 'new_pp' in the example) and is then immediately dereferenced
/// on the subsequent line if a preceding function call fails (e.g., if
/// of_changeset_add_property() fails).
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