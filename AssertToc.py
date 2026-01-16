from binaryninja import PossibleValueSet, log, BackgroundTaskThread, BinaryView

class AssertTocTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(self, 'Waiting for analysis for finish...', False)
        self.bv = bv

    def run(self):
        log.log_info("Iterating .opd")

        opd_section = self.bv.get_section_by_name(".opd")
        opd_entry_count = opd_section.length // 8

        for i in range(opd_entry_count):
            offset = opd_section.start + (i * 8)
            entry = self.bv.get_data_var_at(offset)
            addr = entry["func_entry"].value

            func = self.bv.get_function_at(addr)
            if(not func.mlil_if_available):
                continue

            found = False

            if(len(func.type.parameters) > 0 and func.type.parameters_with_all_locations[0].location.name == "r2"):
                for il in func.mlil:
                    if found: break
                    for il in il:
                        if found: break
                        for var in il.vars_read:
                            if found: break
                            if var.name == "arg1":
                                toc_base = PossibleValueSet.constant_ptr(entry["toc_base"].value)
                                func.set_user_var_value(var, il.address, toc_base, after=False)
                                found = True
                                break
                continue
    log.log_info("Finished iterating .opd")