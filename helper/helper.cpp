#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>

#include <iostream>


#include <class_linker.h>
#include <runtime.h>
#include <art_method.h>
#include <art_method-inl.h>


#include <instrumentation.h>
#include <dlfcn.h>
#include <gc/scoped_gc_critical_section.h>
#include <base/enums.h>

#include <scoped_thread_state_change-inl.h>
#include <thread_list.h>
#include <thread_state.h>
//#include <base/mutex.cc>


using art::PointerSize;
using art::ThreadState;
using art::Runtime;
using art::ArtMethod;
using art::ShadowFrame;
using art::Thread;
using art::instrumentation::Instrumentation;
using art::instrumentation::InstrumentationStackFrame;
using art::instrumentation::InstrumentationListener;
using art::instrumentation::InterpreterHandlerTable;
using art::ScopedThreadSuspension;
using art::ScopedObjectAccess;
using art::jit::Jit;
using art::DexFile;
using art::mirror::Class;
using art::mirror::Object;
using art::mirror::DexCache;
//using art::DexFile::MethodId;


//using namespace std;
 //const char* ArtMethod::GetShorty()
typedef  const char* (ArtMethod::*getShortyMethods) ();
//inline ArtMethod* ArtMethod::GetInterfaceMethodIfProxy(PointerSize pointer_size)
typedef  ArtMethod* (ArtMethod::*getInterfaceIfproxyMethods) (PointerSize pointer_size);

 
 // FPTR fptr = &Foo::f;

typedef void (*instrumentation_add_listener_t)(InstrumentationListener* listener, uint32_t events);

extern "C"
{

/*
bool have_invoke_virtual_or_interface_listeners_ GUARDED_BY(Locks::mutator_lock_);

  // Contains the instrumentation level required by each client of the instrumentation identified
  // by a string key.
  typedef SafeMap<const char*, InstrumentationLevel> InstrumentationLevelTable;
  InstrumentationLevelTable requested_instrumentation_levels_ GUARDED_BY(Locks::mutator_lock_);

  // The event listeners, written to with the mutator_lock_ exclusively held.
  // Mutators must be able to iterate over these lists concurrently, that is, with listeners being
  // added or removed while iterating. The modifying thread holds exclusive lock,
  // so other threads cannot iterate (i.e. read the data of the list) at the same time but they
  // do keep iterators that need to remain valid. This is the reason these listeners are std::list
  // and not for example std::vector: the existing storage for a std::list does not move.
  // Note that mutators cannot make a copy of these lists before iterating, as the instrumentation
  // listeners can also be deleted concurrently.
  // As a result, these lists are never trimmed. That's acceptable given the low number of
  // listeners we have.
  std::list<InstrumentationListener*> method_entry_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> method_exit_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> method_unwind_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> branch_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> invoke_virtual_or_interface_listeners_
      GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> dex_pc_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> field_read_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> field_write_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListene
bool have_invoke_virtual_or_interface_listeners_ GUARDED_BY(Locks::mutator_lock_);

  // Contains the instrumentation level required by each client of the instrumentation identified
  // by a string key.
  typedef SafeMap<const char*, InstrumentationLevel> InstrumentationLevelTable;
  InstrumentationLevelTable requested_instrumentation_levels_ GUARDED_BY(Locks::mutator_lock_);

  // The event listeners, written to with the mutator_lock_ exclusively held.
  // Mutators must be able to iterate over these lists concurrently, that is, with listeners being
  // added or removed while iterating. The modifying thread holds exclusive lock,
  // so other threads cannot iterate (i.e. read the data of the list) at the same time but they
  // do keep iterators that need to remain valid. This is the reason these listeners are std::list
  // and not for example std::vector: the existing storage for a std::list does not move.
  // Note that mutators cannot make a copy of these lists before iterating, as the instrumentation
  // listeners can also be deleted concurrently.
  // As a result, these lists are never trimmed. That's acceptable given the low number of
  // listeners we have.
  std::list<InstrumentationListener*> method_entry_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> method_exit_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> method_unwind_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> branch_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> invoke_virtual_or_interface_listeners_
      GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> dex_pc_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> field_read_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> field_write_listeners_ GUARDED_BY(Locks::mutator_lock_);
  std::list<InstrumentationListener*> exception_caught_listeners_ GUARDED_BY(Locks::mutator_lock_);

  // The set of methods being deoptimized (by the debugger) which must be executed with interpreter
  // only.
  mutable ReaderWriterMutex deoptimized_methods_lock_ DEFAULT_MUTEX_ACQUIRED_AFTER;
  std::unordered_set<ArtMethod*> deoptimized_methods_ GUARDED_BY(deoptimized_methods_lock_);
  bool deoptimization_enabled_;
  printing offset of all this*/


 unsigned int
  ath_get_offset_of_instrumentation_requested_instrumentation_levels_()
  {
    return offsetof(Instrumentation, requested_instrumentation_levels_);
  }  
 unsigned int
  ath_get_offset_of_instrumentation_method_entry_listeners_()
  {
    return offsetof(Instrumentation, method_entry_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_method_exit_listeners_()
  {
    return offsetof(Instrumentation, method_exit_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_method_unwind_listeners_()
  {
    return offsetof(Instrumentation, method_unwind_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_branch_listeners_()
  {
    return offsetof(Instrumentation, branch_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_invoke_virtual_or_interface_listeners_()
  {
    return offsetof(Instrumentation, invoke_virtual_or_interface_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_field_read_listeners_()
  {
    return offsetof(Instrumentation, field_read_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_field_write_listeners_()
  {
    return offsetof(Instrumentation, field_write_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_exception_caught_listeners_()
  {
    return offsetof(Instrumentation, exception_caught_listeners_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_deoptimized_methods_lock_listeners_()
  {
    return offsetof(Instrumentation, deoptimized_methods_lock_);
  }  
   unsigned int
  ath_get_offset_of_instrumentation_deoptimized_methods_listeners_()
  {
    return offsetof(Instrumentation, deoptimized_methods_);
  }  









/*bool Instrumentation::IsDeoptimizedMethodsEmpty() const {
  return deoptimized_methods_.empty();
}*/
bool  ath_instrumentation_has_deoptimized_methods_empty_ (Instrumentation* instrumentation){
  return instrumentation->IsDeoptimizedMethodsEmpty();
}








  unsigned int
  ath_get_offset_of_alloc_entrypoints_instrumented_()
  {
    return offsetof(Instrumentation, alloc_entrypoints_instrumented_);
  }  
  unsigned int
  ath_get_offset_of_instrumentation_deoptimization_enabled_()
  {
    return offsetof(Instrumentation, deoptimization_enabled_);
  }  

  bool
  ath_instrumentation_deoptimization_enabled_with_my_offset(Instrumentation* instrumentation){
    bool result = instrumentation->deoptimization_enabled_;
    return result; 
  }

  bool 
  ath_instrumentation_deoptimization_enabled(Instrumentation* instrumentation) {
    //return instrumentation->HasMethodEntryListeners();
    return instrumentation->deoptimization_enabled_ ;
  }

  bool 
  ath_instrumentation_have_method_entry_listeners_(Instrumentation * instrumentation){
    return instrumentation->HasMethodEntryListeners();
  }

  unsigned int
  ath_get_offset_of_instrumentation_stubs_installed_()
  {
    return offsetof(Instrumentation, instrumentation_stubs_installed_);
  }  

   unsigned int
  ath_get_offset_of_entry_exit_stubs_installed_()
  {
    return offsetof(Instrumentation, entry_exit_stubs_installed_);
  }  

  void 
  ath_instrumentation_enable_deoptimization(Instrumentation* instrumentation) {
    instrumentation->EnableDeoptimization();
  }






  

  ArtMethod*
  ath_get_method_try_call_get_interface_if_proxy(ArtMethod* m){
    return m->GetInterfaceMethodIfProxy(art::kRuntimePointerSize);
  }
  const char*
  ath_get_method_try_call_shorty(ArtMethod* m){
    return m->GetShorty();
  }
  getShortyMethods
  ath_get_shorty_address(){
    return &ArtMethod::GetShorty;
   //return m->*getShorty;
  }

  getInterfaceIfproxyMethods
  ath_get_interface_if_proxy_address(){
   return &ArtMethod::GetInterfaceMethodIfProxy;
  }

  unsigned int 
  ath_get_method_field_(){
    return offsetof(ArtMethod, dex_method_index_);
  }

  unsigned int 
  ath_get_memory_order_relaxed(){
    return std::memory_order_relaxed;
  }

  unsigned int 
  ath_get_jit_activated(Runtime * runtime){
      Jit* jit = runtime->GetJit();
        if (jit != nullptr) {
            return 1;//Jit is activated
        }
        return 0;// Jit is not activated 
  }

   unsigned int
  ath_get_offset_of_class_iftable_()
  {
    return offsetof(DexFile, type_ids_);
    //return offsetof(art::Runtime, pre_allocated_OutOfMemoryError_);
    //return offsetof(art::DexFile::MethodId, proto_idx_);
    //return offsetof(Runtime, class_linker_);
    //return offsetof(DexFile, begin_);
    //return offsetof(DexCache, dex_file_);
    //return offsetof (Class, iftable_);
    //return offsetof (Class, dex_cache_);
    //return offsetof (Class, iftable_);
  }


  unsigned int
  ath_get_offset_of_code_item_ins_size_()
  {
    return offsetof (DexFile::CodeItem, ins_size_);
    //return sizeof(Instrumentation);
  }

  unsigned int
  ath_get_offset_of_shadow_frame_dex_pc_ptr_ ()
  {
    return offsetof (ShadowFrame, dex_pc_ptr_);
    //return sizeof(Instrumentation);
  }

  unsigned int
  ath_get_offset_of_shadow_frame_dex_pc_ ()
  {
    return offsetof (ShadowFrame, dex_pc_);
    //return sizeof(Instrumentation);
  }
  
  unsigned char * 
  ath_get_address_of_instrumentation_add_listener ()
  {
    void* handle = dlopen("/system/lib/libart.so", RTLD_GLOBAL);
    if (!handle) {
        //cerr << "Cannot open library: " << dlerror() << '\n';
        
        return (unsigned char *) 1;
    }
   

    // reset errors
    dlerror();
    instrumentation_add_listener_t instrumentation_add_listener = (instrumentation_add_listener_t) dlsym(handle, "_ZN3art15instrumentation15Instrumentation11AddListenerEPNS0_23InstrumentationListenerEj");
    const char *dlsym_error = dlerror();
    if (dlsym_error) {
       // cerr << "Cannot load symbol 'hello': " << dlsym_error <<
        dlclose(handle);
        return (unsigned char *) 2;
    }
    return (unsigned char *) instrumentation_add_listener;
  }

  unsigned int 
  ath_get_shadow_frame_vregs_(){
    return offsetof(ShadowFrame, number_of_vregs_);
    //return offsetof(ShadowFrame, vregs_);
  }

  unsigned int
  ath_get_offset_of_runtime_instrumentation ()
  {
    
    int n = 10, i = 0;
    int *piBuffer = NULL;
    //creating integer of size n.
    piBuffer = (int*) malloc(n * sizeof(int));
    //int piBuffer[10] ;
    //Assigned value to allocated memory
    for (i = 0; i < n; ++i)
    {
      piBuffer [i] = i * 3;
    }
    free(piBuffer);
    
    return -0.0/0;//offsetof (Runtime, instrumentation_);
    //return sizeof(Instrumentation);
  }
  unsigned int
  ath_get_offset_of_runtime_fingerprint ()
  {
    return offsetof (Runtime, fingerprint_);
  }
  unsigned int
  ath_get_offset_of_runtime_oat_file_manager_ ()
  {
    return offsetof (Runtime, oat_file_manager_);
  }

 ///////// tow problems
  void 
  ath_instrumentation_deoptimize_everything(Instrumentation* instrumentation, const char* key) {
    instrumentation->DeoptimizeEverything(key);
  }


  void   
  ath_instrumentation_force_interpret_only(Instrumentation* instrumentation) {
    instrumentation->ForceInterpretOnly();
  }

  void 
  ath_instrumentation_disable_deoptimization(Instrumentation* instrumentation,const char* key ) {
    instrumentation->DisableDeoptimization(key);
  }


  void 
  ath_prepare_call_deoptimisation(Instrumentation* instrumentation, const char* key, Thread * thread) {
    
    //ScopedObjectAccess soa(thread);
    /*ScopedThreadSuspension sts(self,ThreadState::kSuspended);*/
    /*art::gc::ScopedGCCriticalSection gcs(self,
                                art::gc::kGcCauseInstrumentation,
                                art::gc::kCollectorTypeInstrumentation);
    art::ScopedSuspendAll ssa("Full deoptimization");*/
    //instrumentation->DeoptimizeEverything(key);
  }
  /*DexFile::CodeItem* 
  ath_method_get_code_item(ArtMethod* method){
    return (DexFile::CodeItem*) method->GetCodeItem();
  }*/


  unsigned int
  ath_get_offset_of_runtime_dump_gc_performance_on_shutdown_ ()
  {
    return offsetof(Runtime, dump_gc_performance_on_shutdown_);
  }


 


///////// 

  InstrumentationStackFrame *
  ath_thread_get_instrumentation_stack_front (Thread * thread)
  {
    return &thread->GetInstrumentationStack ()->front ();
  }

  InstrumentationStackFrame *
  ath_thread_get_instrumentation_stack_back (Thread * thread)
  {
    return &thread->GetInstrumentationStack ()->back ();
  }
};
