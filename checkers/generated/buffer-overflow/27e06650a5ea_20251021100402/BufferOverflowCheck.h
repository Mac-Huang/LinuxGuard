//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_LINUXKERNEL_BUFFER_OVERFLOW_CHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_LINUXKERNEL_BUFFER_OVERFLOW_CHECK_H

#include "../ClangTidyCheck.h"

namespace clang::tidy::linuxkernel {

/// Checks for buffer overflows in the `target_lu_gp_members_show` function.
/// Specifically, it detects if the `snprintf` function writes data into the
/// `buf` buffer without proper bounds checking before a potential `memcpy`
/// call, which can lead to a buffer overflow.
///
/// For the user-facing documentation see:
/// https://clang.llvm.org/extra/clang-tidy/checks/linuxkernel/buffer-overflow.html
class BufferOverflowCheck : public ClangTidyCheck {
public:
  BufferOverflowCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace clang::tidy::linuxkernel

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_LINUXKERNEL_BUFFER_OVERFLOW_CHECK_H