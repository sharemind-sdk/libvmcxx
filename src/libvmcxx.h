/*
 * Copyright (C) 2015 Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#ifndef SHAREMIND_LIBVMCXX_LIBVMCXX_H
#define SHAREMIND_LIBVMCXX_LIBVMCXX_H

#include <cassert>
#include <exception>
#include <new>
#include <sharemind/compiler-support/GccPR54526.h>
#include <sharemind/compiler-support/GccPR55015.h>
#include <sharemind/FunctionTraits.h>
#include <sharemind/VoidT.h>
#include <type_traits>
#include <utility>
#include "libvm.h"


namespace sharemind {

/*******************************************************************************
  Some type aliases
*******************************************************************************/

using VmContext = ::SharemindVirtualMachineContext;
using VmInstruction = ::SharemindVmInstruction;


/*******************************************************************************
  VmError
*******************************************************************************/

using VmError = ::SharemindVmError;
inline const char * VmError_toString(const VmError e) noexcept
{ return ::SharemindVmError_toString(e); }


/*******************************************************************************
  Forward declarations:
*******************************************************************************/

class Vm;
class Program;
class Process;


/*******************************************************************************
  Some helper macros
*******************************************************************************/

#define SHAREMIND_LIBVM_CXX_DEFINE_PARENT_GETTER(ClassName,Parent,parent) \
    inline Parent * parent() const noexcept { \
        return Detail::libvm::mustTag( \
                ::Sharemind ## ClassName ## _ ## parent(m_c)); \
    }

#define SHAREMIND_LIBVM_CXX_DEFINE_CPTR_GETTERS(ClassName) \
    inline ::Sharemind ## ClassName * cPtr() noexcept { return m_c; } \
    inline const ::Sharemind ## ClassName * cPtr() const noexcept \
    { return m_c; }

#define SHAREMIND_LIBVM_CXX_DEFINE_EXCEPTION(ClassName) \
    class Exception: public VmExceptionBase { \
    public: /* Methods: */ \
        inline Exception(const ::Sharemind ## ClassName & c) \
            : VmExceptionBase( \
                      Detail::libvm::allocThrow( \
                              ::Sharemind ## ClassName ## _lastError(&c)), \
                      ::Sharemind ## ClassName ## _lastErrorString(&c)) \
        {} \
        inline Exception(const ClassName & c) : Exception(*(c.cPtr())) {} \
        inline Exception(const VmError error, const char * const errorStr) \
            : VmExceptionBase(error, errorStr) \
        {} \
        inline Exception(const VmError error, \
                         const ::Sharemind ## ClassName & c) \
            : VmExceptionBase(error, \
                              ::Sharemind ## ClassName ## _lastErrorString(&c))\
        {} \
        inline Exception(const VmError error, const ClassName & c) \
            : Exception(error, *(c.cPtr())) \
        {} \
    }


/*******************************************************************************
  Details
*******************************************************************************/

namespace Detail {
namespace libvm {

inline VmError allocThrow(const VmError e) {
    if (e == ::SHAREMIND_VM_OUT_OF_MEMORY)
        throw std::bad_alloc();
    return e;
}

template <typename CType> struct TypeInv;

#define SHAREMIND_LIBVM_CXX_DEFINE_TYPEINV(t) \
    template <> struct TypeInv<t> { using type = ::Sharemind ## t; };\
    template <> struct TypeInv<SHAREMIND_GCCPR54526::Sharemind ## t> \
    { using type = t; };

#define SHAREMIND_LIBVM_CXX_DEFINE_TAGGETTER(type) \
    inline type * getTag(const ::Sharemind ## type * const o) noexcept \
    { return static_cast<type *>(::Sharemind ## type ## _tag(o)); }

#define SHAREMIND_LIBVM_CXX_DEFINE_TYPE_STUFF(type) \
    SHAREMIND_LIBVM_CXX_DEFINE_TYPEINV(type) \
    SHAREMIND_LIBVM_CXX_DEFINE_TYPEINV(type const) \
    SHAREMIND_LIBVM_CXX_DEFINE_TYPEINV(type volatile) \
    SHAREMIND_LIBVM_CXX_DEFINE_TYPEINV(type const volatile) \
    SHAREMIND_LIBVM_CXX_DEFINE_TAGGETTER(type)

SHAREMIND_LIBVM_CXX_DEFINE_TYPE_STUFF(Vm)
SHAREMIND_LIBVM_CXX_DEFINE_TYPE_STUFF(Program)
SHAREMIND_LIBVM_CXX_DEFINE_TYPE_STUFF(Process)

#undef SHAREMIND_LIBVM_CXX_DEFINE_TYPE_STUFF
#undef SHAREMIND_LIBVM_CXX_DEFINE_TAGGETTER
#undef SHAREMIND_LIBVM_CXX_DEFINE_TYPEINV

template <typename CType>
inline typename TypeInv<CType>::type * mustTag(CType * const ssc) noexcept {
    assert(ssc);
    typename TypeInv<CType>::type * const sc = getTag(ssc);
    return (assert(sc), sc);
}

template <typename CType>
inline typename TypeInv<CType>::type * optChild(CType * const ssc) noexcept
{ return ssc ? mustTag(ssc) : nullptr; }

template <typename T>
using FindSyscallT =
        decltype(std::declval<T &>()(std::declval<const char *>()));

template <typename T>
using FindPdT =
        decltype(std::declval<T &>()(std::declval<const char *>()));

template <typename T, typename = void>
struct IsFindSyscall: std::false_type {};

template <typename T>
struct IsFindSyscall<T, VoidT<FindSyscallT<T> > >
        : std::is_same<typename FunctionTraits<
                           decltype(std::declval<VmContext *>()
                                        ->find_syscall)>::return_type,
                       FindSyscallT<T> >
{};

template <typename T, typename = void>
struct IsFindPd: std::false_type {};

template <typename T>
struct IsFindPd<T, VoidT<FindSyscallT<T> > >
        : std::is_same<typename FunctionTraits<
                           decltype(std::declval<VmContext *>()
                                        ->find_pd)>::return_type,
                       FindPdT<T> >
{};

template <typename F,
          unsigned =
              std::conditional<
                  IsFindSyscall<F>::type::value,
                  std::integral_constant<unsigned, 1u>::type,
                  typename std::conditional<
                      IsFindPd<F>::type::value,
                      std::integral_constant<unsigned, 2u>::type,
                      std::integral_constant<unsigned, 0u>::type
                  >::type
              >::type::value>
struct CustomContext1;

template <typename F>
struct CustomContext1<F, 1u>: VmContext {

    /* Types: */

    struct Inner { F f; };

    /* Methods: */

    template <typename F_>
    inline CustomContext1(F_ && f)
        : VmContext{new Inner{std::forward<F_>(f)},
                    [](VmContext * c) noexcept {
                        delete static_cast<Inner *>(c->internal);
                        delete static_cast<CustomContext1<F> *>(c);
                    },
                    [](VmContext * c, const char * name) noexcept
                    { return static_cast<Inner *>(c->internal)->f(name); },
                    nullptr}
    {}
};

template <typename F>
struct CustomContext1<F, 2u>: VmContext {

    /* Types: */

    struct Inner { F f; };

    /* Methods: */

    template <typename F_>
    inline CustomContext1(F_ && f)
        : VmContext{new Inner{std::forward<F_>(f)},
                    [](VmContext * c) noexcept {
                        delete static_cast<Inner *>(c->internal);
                        delete static_cast<CustomContext1<F> *>(c);
                    },
                    nullptr,
                    [](VmContext * c, const char * name) noexcept
                    { return static_cast<Inner *>(c->internal)->f(name); }}
    {}
};

template <typename FindSyscall, typename FindPd>
struct CustomContext2: VmContext {

/* Types: */

    struct Inner {
        FindSyscall findSyscall;
        FindPd findPd;
    };

/* Methods: */

    template <typename FindSyscall_, typename FindPd_>
    inline CustomContext2(FindSyscall_ && findSyscall, FindPd_ && findPd)
        : VmContext{new Inner{std::forward<FindSyscall_>(findSyscall),
                              std::forward<FindPd_>(findPd)},
                    &staticDestructor,
                    &staticFindSyscall,
                    &staticFindPd}
    {}

private: /* Methods: */

    static void staticDestructor(VmContext * c) noexcept {
        delete static_cast<Inner *>(c->internal);
        delete static_cast<CustomContext2<FindSyscall,
                                          FindPd> *>(c);
    }

    static SharemindSyscallWrapper staticFindSyscall(VmContext * c,
                                                     const char * n)
    { return static_cast<Inner *>(c->internal)->findSyscall(n); }

    static SharemindPd * staticFindPd(VmContext * c, const char * n)
    { return static_cast<Inner *>(c->internal)->findPd(n); }

};

} /* namespace libvm { */
} /* namespace Detail { */


/*******************************************************************************
  VmExceptionBase
*******************************************************************************/

class VmExceptionBase: public std::exception {

public: /* Methods: */

    inline VmExceptionBase(const VmError errorCode, const char * const errorStr)
        : m_errorCode((assert(errorCode != ::SHAREMIND_VM_OK), errorCode))
        , m_errorStr(errorStr ? errorStr : VmError_toString(errorCode))
    {}

    inline VmError code() const noexcept { return m_errorCode; }
    inline const char * what() const noexcept override { return m_errorStr; }

private: /* Fields: */

    const VmError m_errorCode;
    const char * const m_errorStr;

}; /* class VmExceptionBase { */


/*******************************************************************************
  Process
*******************************************************************************/

class Process {

public: /* Types: */

    SHAREMIND_LIBVM_CXX_DEFINE_EXCEPTION(Process);

    class RuntimeException: public Exception {

    public: /* Methods: */

        inline RuntimeException(const ::SharemindProcess & process)
            : Exception(::SHAREMIND_VM_RUNTIME_EXCEPTION,
                        process)
            , m_code(::SharemindProcess_exception(&process))
        {}

        ::SharemindVmProcessException exception() const noexcept
        { return m_code; }

    private: /* Fields: */

        ::SharemindVmProcessException m_code;

    };

public: /* Methods: */

    Process() = delete;
    Process(Process &&) = delete;
    Process(const Process &) = delete;
    Process & operator=(Process &&) = delete;
    Process & operator=(const Process &) = delete;

    inline Process(Program & program);

    virtual inline ~Process() noexcept {
        if (m_c) {
            if (::SharemindProcess_tag(m_c) == this)
                ::SharemindProcess_releaseTag(m_c);
            ::SharemindProcess_free(m_c);
        }
    }

    SHAREMIND_LIBVM_CXX_DEFINE_CPTR_GETTERS(Process)
    SHAREMIND_LIBVM_CXX_DEFINE_PARENT_GETTER(Process,Program,program)
    SHAREMIND_LIBVM_CXX_DEFINE_PARENT_GETTER(Process,Vm,vm)

    size_t pdpiCount() const noexcept
    { return ::SharemindProcess_pdpiCount(m_c); }

    ::SharemindPdpi * pdpi(const size_t pdpiIndex) const noexcept
    { return ::SharemindProcess_pdpi(m_c, pdpiIndex); }

    void setPdpiFacility(const char * const name,
                         void * const facility,
                         void * const context = nullptr)
            __attribute__((nonnull(2)))
    {
        const VmError r = ::SharemindProcess_setPdpiFacility(m_c,
                                                             name,
                                                             facility,
                                                             context);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void setInternal(void * const value) noexcept
    { ::SharemindProcess_setInternal(m_c, value); }

    void run() { run__<&::SharemindProcess_run>(); }

    void continueRun() { run__<&::SharemindProcess_continue>(); }

    void pause() {
        const VmError r = ::SharemindProcess_pause(m_c);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    int64_t returnValue() const noexcept
    { return ::SharemindProcess_returnValue(m_c); }

    size_t currentCodeSection() const noexcept
    { return ::SharemindProcess_currentCodeSection(m_c); }

    uintptr_t currentIp() const noexcept
    { return ::SharemindProcess_currentIp(m_c); }

private: /* Methods: */

    template <VmError (* runFn)(::SharemindProcess *)>
    void run__() {
        const VmError r = (*runFn)(m_c);
        if (r != ::SHAREMIND_VM_OK) {
            if (r == ::SHAREMIND_VM_RUNTIME_EXCEPTION)
                throw RuntimeException(*m_c);
            throw Exception(r, *m_c);
        }
    }

private: /* Fields: */

    ::SharemindProcess * m_c;

}; /* class Process { */


/*******************************************************************************
  Program
*******************************************************************************/

class Program {

    friend Process::Process(Program & program);

public: /* Types: */

    using Overrides = VmContext;
    SHAREMIND_LIBVM_CXX_DEFINE_EXCEPTION(Program);

public: /* Methods: */

    Program() = delete;
    Program(Program &&) = delete;
    Program(const Program &) = delete;
    Program & operator=(Program &&) = delete;
    Program & operator=(const Program &) = delete;

    inline Program(Vm & vm)
        : Program(vm, static_cast<Overrides *>(nullptr))
    {}

    inline Program(Vm & vm, Overrides & overrides) : Program(vm, &overrides) {}

    template <typename F>
    inline Program(Vm & vm, F && f)
        : Program(vm,
                  static_cast<Overrides *>(
                      new Detail::libvm::CustomContext1<F>{std::forward<F>(f)}))
    {}

    template <typename FindSyscall, typename FindPd>
    inline Program(Vm & vm, FindSyscall && findSyscall, FindPd && findPd)
        : Program(vm,
                  static_cast<Overrides *>(
                      new Detail::libvm::CustomContext2<FindSyscall, FindPd>{
                            std::forward<FindSyscall>(findSyscall),
                            std::forward<FindPd>(findPd)}))
    {}

    virtual inline ~Program() noexcept {
        if (m_c) {
            if (::SharemindProgram_tag(m_c) == this)
                ::SharemindProgram_releaseTag(m_c);
            ::SharemindProgram_free(m_c);
        }
    }

    SHAREMIND_LIBVM_CXX_DEFINE_CPTR_GETTERS(Program)
    SHAREMIND_LIBVM_CXX_DEFINE_PARENT_GETTER(Program,Vm,vm)

    void loadFromFile(const char * filename) {
        assert(filename);
        const VmError r = ::SharemindProgram_loadFromFile(m_c, filename);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void loadFromCFile(FILE * file) {
        assert(file);
        const VmError r = ::SharemindProgram_loadFromCFile(m_c, file);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void loadFromFileDescriptor(const int fd) {
        assert(fd >= 0);
        const VmError r = ::SharemindProgram_loadFromFileDescriptor(m_c, fd);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void loadFromMemory(const void * const data, const size_t size) {
        assert(data);
        const VmError r = ::SharemindProgram_loadFromMemory(m_c, data, size);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    bool isReady() const noexcept { return ::SharemindProgram_isReady(m_c); }

    const void * lastParsePosition() const noexcept
    { return SharemindProgram_lastParsePosition(m_c); }

    const VmInstruction * instruction(const size_t codeSection,
                                      const size_t instructionIndex)
            const noexcept
    {
        return ::SharemindProgram_instruction(m_c,
                                              codeSection,
                                              instructionIndex);
    }

private: /* Methods: */

    inline Program(Vm & vm, Overrides * const overrides);

    inline ::SharemindProcess & newProcess() {
        ::SharemindProcess * const p = ::SharemindProgram_newProcess(m_c);
        if (p)
            return *p;
        throw Exception(*m_c);
    }

private: /* Fields: */

    ::SharemindProgram * m_c;

}; /* class Program { */


/*******************************************************************************
  Vm
*******************************************************************************/

class Vm {

    friend class Program;

public: /* Types: */

    using Context = VmContext;

    SHAREMIND_LIBVM_CXX_DEFINE_EXCEPTION(Vm);

public: /* Methods: */

    Vm(Vm &&) = delete;
    Vm(const Vm &) = delete;
    Vm & operator=(Vm &&) = delete;
    Vm & operator=(const Vm &) = delete;

    inline Vm() : Vm(static_cast<Context *>(nullptr)) {}
    inline Vm(Context & context) : Vm(&context) {}

    template <typename F>
    inline Vm(F && f)
        : Vm(static_cast<Context *>(
                 new Detail::libvm::CustomContext1<F>{std::forward<F>(f)}))
    {}

    template <typename FindSyscall, typename FindPd>
    inline Vm(FindSyscall && findSyscall, FindPd && findPd)
        : Vm(static_cast<Context *>(
                 new Detail::libvm::CustomContext2<FindSyscall, FindPd>{
                            std::forward<FindSyscall>(findSyscall),
                            std::forward<FindPd>(findPd)}))
    {}

    virtual inline ~Vm() noexcept {
        if (m_c) {
            if (::SharemindVm_tag(m_c) == this)
                ::SharemindVm_releaseTag(m_c);
            ::SharemindVm_free(m_c);
        }
    }

    SHAREMIND_LIBVM_CXX_DEFINE_CPTR_GETTERS(Vm)

private: /* Methods: */

    inline Vm(Context * const context)
        : m_c([context](){
            VmError error;
            const char * errorStr;
            ::SharemindVm * const vm =
                    ::SharemindVm_new(context, &error, &errorStr);
            if (vm)
                return vm;
            throw Exception(Detail::libvm::allocThrow(error), errorStr);
        }())
    {
        #define SHAREMIND_LIBVM_CXX_VM_L1 \
            (void * m) noexcept { \
                Vm * const vm = static_cast<Vm *>(m); \
                vm->m_c = nullptr; \
                delete vm; \
            }
        #if SHAREMIND_GCCPR55015
        struct F { static void f SHAREMIND_LIBVM_CXX_VM_L1 };
        #endif
        ::SharemindVm_setTagWithDestructor(
                    m_c,
                    this,
                    #if SHAREMIND_GCCPR55015
                    &F::f
                    #else
                    []SHAREMIND_LIBVM_CXX_VM_L1
                    #endif
                    );
        #undef SHAREMIND_LIBVM_CXX_VM_L1
    }

    inline ::SharemindProgram & newProgram(Program::Overrides * const overrides) {
        ::SharemindProgram * const p =
                ::SharemindVm_newProgram(m_c, overrides);
        if (p)
            return *p;
        throw Exception(*m_c);
    }

private: /* Fields: */

    ::SharemindVm * m_c;

}; /* class Vm { */


/*******************************************************************************
  Program methods
*******************************************************************************/

inline Program::Program(Vm & vm, Overrides * const overrides)
    : m_c(&vm.newProgram(overrides))
{
    try {
        #define SHAREMIND_LIBVM_CXX_PROGRAM_L1 \
            (void * program) noexcept { \
                Program * const p = static_cast<Program *>(program); \
                p->m_c = nullptr; \
                delete p; \
            }
        #if SHAREMIND_GCCPR55015
        struct F { static void f SHAREMIND_LIBVM_CXX_PROGRAM_L1 };
        #endif
        ::SharemindProgram_setTagWithDestructor(
                    m_c,
                    this,
                    #if SHAREMIND_GCCPR55015
                    &F::f
                    #else
                    []SHAREMIND_LIBVM_CXX_PROGRAM_L1
                    #endif
                    );
        #undef SHAREMIND_LIBVM_CXX_PROGRAM_L1
    } catch (...) {
        ::SharemindProgram_free(m_c);
        throw;
    }
}


/*******************************************************************************
  Process methods
*******************************************************************************/

inline Process::Process(Program & program)
    : m_c(&program.newProcess())
{
    try {
        #define SHAREMIND_LIBVM_CXX_PROCESS_L1 \
            (void * process) noexcept { \
                Process * const p = static_cast<Process *>(process); \
                p->m_c = nullptr; \
                delete p; \
            }
        #if SHAREMIND_GCCPR55015
        struct F { static void f SHAREMIND_LIBVM_CXX_PROCESS_L1 };
        #endif
        ::SharemindProcess_setTagWithDestructor(
                    m_c,
                    this,
                    #if SHAREMIND_GCCPR55015
                    &F::f
                    #else
                    []SHAREMIND_LIBVM_CXX_PROCESS_L1
                    #endif
                    );
        #undef SHAREMIND_LIBVM_CXX_PROCESS_L1
    } catch (...) {
        ::SharemindProcess_free(m_c);
        throw;
    }
}


/*******************************************************************************
  Clean up helper macros
*******************************************************************************/

#undef SHAREMIND_LIBVM_CXX_DEFINE_EXCEPTION
#undef SHAREMIND_LIBVM_CXX_DEFINE_CPTR_GETTERS
#undef SHAREMIND_LIBVM_CXX_DEFINE_PARENT_GETTER


} /* namespace sharemind { */

#endif /* SHAREMIND_LIBVMCXX_LIBVMCXX_H */
