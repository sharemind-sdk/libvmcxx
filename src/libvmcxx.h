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
inline char const * VmError_toString(VmError const e) noexcept
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
    inline ::Sharemind ## ClassName const * cPtr() const noexcept \
    { return m_c; }

#define SHAREMIND_LIBVM_CXX_DEFINE_EXCEPTION(ClassName) \
    class Exception: public VmExceptionBase { \
    public: /* Methods: */ \
        inline Exception(::Sharemind ## ClassName const & c) \
            : VmExceptionBase( \
                      Detail::libvm::allocThrow( \
                              ::Sharemind ## ClassName ## _lastError(&c)), \
                      ::Sharemind ## ClassName ## _lastErrorString(&c)) \
        {} \
        inline Exception(ClassName const & c) : Exception(*(c.cPtr())) {} \
        inline Exception(VmError const error, char const * const errorStr) \
            : VmExceptionBase(error, errorStr) \
        {} \
        inline Exception(VmError const error, \
                         ::Sharemind ## ClassName const & c) \
            : VmExceptionBase(error, \
                              ::Sharemind ## ClassName ## _lastErrorString(&c))\
        {} \
        inline Exception(VmError const error, ClassName const & c) \
            : Exception(error, *(c.cPtr())) \
        {} \
    }


/*******************************************************************************
  Details
*******************************************************************************/

namespace Detail {
namespace libvm {

inline VmError allocThrow(VmError const e) {
    if (e == ::SHAREMIND_VM_OUT_OF_MEMORY)
        throw std::bad_alloc();
    return e;
}

template <typename CType> struct TypeInv;

#define SHAREMIND_LIBVM_CXX_DEFINE_TYPEINV(t) \
    template <> struct TypeInv<t> { using type = ::Sharemind ## t; };\
    template <> struct TypeInv<SHAREMIND_GCCPR54526_WORKAROUND::Sharemind ## t>\
    { using type = t; };

#define SHAREMIND_LIBVM_CXX_DEFINE_TAGGETTER(type) \
    inline type * getTag(::Sharemind ## type const * const o) noexcept \
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
        decltype(std::declval<T &>()(std::declval<char const *>()));

template <typename T>
using FindPdT =
        decltype(std::declval<T &>()(std::declval<char const *>()));

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
class CustomContext1;
template <typename FindSyscall, typename FindPd> class CustomContext2;

class CustomContextBase: public VmContext {

    template <typename, unsigned> friend class CustomContext1;
    template <typename, typename> friend class CustomContext2;

protected: /* Methods: */

    template <typename InnerPtr,
              typename Destructor,
              typename FindSyscall,
              typename FindPd>
    CustomContextBase(InnerPtr && innerPtr,
                      Destructor && destructor,
                      FindSyscall && findSyscall,
                      FindPd && findPd)
        : VmContext{std::forward<InnerPtr>(innerPtr),
                    std::forward<Destructor>(destructor),
                    std::forward<FindSyscall>(findSyscall),
                    std::forward<FindPd>(findPd)}
    {}

private: /* Methods: */

    template <typename Inner, typename Subclass>
    static void staticDestructor(VmContext * c) noexcept {
        delete static_cast<Inner *>(c->internal);
        delete static_cast<Subclass *>(c);
    }

    template <typename Inner>
    static SharemindSyscallWrapper staticFindSyscall(VmContext * c,
                                                     char const * name) noexcept
    { return static_cast<Inner *>(c->internal)->findSyscall(name); }

    template <typename Inner>
    static SharemindPd * staticFindPd(VmContext * c, char const * name) noexcept
    { return static_cast<Inner *>(c->internal)->findPd(name); }

};

template <typename FindSyscall>
class CustomContext1<FindSyscall, 1u>: public CustomContextBase {

private: /* Types: */

    struct Inner { FindSyscall findSyscall; };

public: /* Methods: */

    template <typename FindSyscall_>
    inline CustomContext1(FindSyscall_ && f)
        : CustomContextBase{new Inner{std::forward<FindSyscall_>(f)},
                            &CustomContextBase::staticDestructor<
                                Inner,
                                CustomContext1<FindSyscall, 1u> >,
                            &CustomContextBase::staticFindSyscall<Inner>,
                            nullptr}
    {}

};

template <typename FindPd>
class CustomContext1<FindPd, 2u>: public CustomContextBase {

private: /* Types: */

    struct Inner { FindPd findPd; };

public: /* Methods: */

    template <typename FindPd_>
    inline CustomContext1(FindPd_ && f)
        : CustomContextBase{new Inner{std::forward<FindPd_>(f)},
                            &CustomContextBase::staticDestructor<
                                Inner,
                                CustomContext1<FindPd, 2u> >,
                            nullptr,
                            &CustomContextBase::staticFindPd<Inner>}
    {}

};

template <typename FindSyscall, typename FindPd>
class CustomContext2: public CustomContextBase {

private: /* Types: */

    struct Inner {
        FindSyscall findSyscall;
        FindPd findPd;
    };

public: /* Methods: */

    template <typename FindSyscall_, typename FindPd_>
    inline CustomContext2(FindSyscall_ && findSyscall, FindPd_ && findPd)
        : CustomContextBase{new Inner{std::forward<FindSyscall_>(findSyscall),
                                      std::forward<FindPd_>(findPd)},
                            &CustomContextBase::staticDestructor<
                                Inner,
                                CustomContext2<FindSyscall, FindPd> >,
                            &CustomContextBase::staticFindSyscall<Inner>,
                            &CustomContextBase::staticFindPd<Inner>}
    {}

};

} /* namespace libvm { */
} /* namespace Detail { */


/*******************************************************************************
  VmExceptionBase
*******************************************************************************/

class VmExceptionBase: public std::exception {

public: /* Methods: */

    inline VmExceptionBase(VmError const errorCode, char const * const errorStr)
        : m_errorCode((assert(errorCode != ::SHAREMIND_VM_OK), errorCode))
        , m_errorStr(errorStr ? errorStr : VmError_toString(errorCode))
    {}

    inline VmError code() const noexcept { return m_errorCode; }
    inline char const * what() const noexcept override { return m_errorStr; }

private: /* Fields: */

    VmError const m_errorCode;
    char const * const m_errorStr;

}; /* class VmExceptionBase { */


/*******************************************************************************
  Process
*******************************************************************************/

class Process {

public: /* Types: */

    SHAREMIND_LIBVM_CXX_DEFINE_EXCEPTION(Process);

    class RuntimeException: public Exception {

    public: /* Methods: */

        inline RuntimeException(::SharemindProcess const & process)
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
    Process(Process const &) = delete;
    Process & operator=(Process &&) = delete;
    Process & operator=(Process const &) = delete;

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

    ::SharemindPdpi * pdpi(size_t const pdpiIndex) const noexcept
    { return ::SharemindProcess_pdpi(m_c, pdpiIndex); }

    void setPdpiFacility(char const * const name,
                         void * const facility,
                         void * const context = nullptr)
            __attribute__((nonnull(2)))
    {
        VmError const r = ::SharemindProcess_setPdpiFacility(m_c,
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

    void pause() { ::SharemindProcess_pause(m_c); }

    template <typename SyscallExceptionType>
    SyscallExceptionType const & syscallException() const noexcept {
        using T = SyscallExceptionType const;
        return *static_cast<T *>(::SharemindProcess_syscallException(m_c));
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
        VmError const r = (*runFn)(m_c);
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
    Program(Program const &) = delete;
    Program & operator=(Program &&) = delete;
    Program & operator=(Program const &) = delete;

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

    void loadFromFile(char const * filename) {
        assert(filename);
        VmError const r = ::SharemindProgram_loadFromFile(m_c, filename);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void loadFromCFile(FILE * file) {
        assert(file);
        VmError const r = ::SharemindProgram_loadFromCFile(m_c, file);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void loadFromFileDescriptor(int const fd) {
        assert(fd >= 0);
        VmError const r = ::SharemindProgram_loadFromFileDescriptor(m_c, fd);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void loadFromMemory(void const * const data, size_t const size) {
        assert(data);
        VmError const r = ::SharemindProgram_loadFromMemory(m_c, data, size);
        if (r != ::SHAREMIND_VM_OK)
            throw Exception(r, *m_c);
    }

    void load(char const * const filename) { return loadFromFile(filename); }
    void load(FILE * const file) { return loadFromCFile(file); }
    void load(int const fd) { return loadFromFileDescriptor(fd); }
    void load(void const * const data, size_t const size)
    { return loadFromMemory(data, size); }

    bool isReady() const noexcept { return ::SharemindProgram_isReady(m_c); }

    void const * lastParsePosition() const noexcept
    { return SharemindProgram_lastParsePosition(m_c); }

    VmInstruction const * instruction(size_t const codeSection,
                                      size_t const instructionIndex)
            const noexcept
    {
        return ::SharemindProgram_instruction(m_c,
                                              codeSection,
                                              instructionIndex);
    }

    size_t pdCount() const noexcept
    { return ::SharemindProgram_pdCount(m_c); }

    ::SharemindPd * pd(size_t const pdIndex) const noexcept
    { return ::SharemindProgram_pd(m_c, pdIndex); }

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
    Vm(Vm const &) = delete;
    Vm & operator=(Vm &&) = delete;
    Vm & operator=(Vm const &) = delete;

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
            char const * errorStr;
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
