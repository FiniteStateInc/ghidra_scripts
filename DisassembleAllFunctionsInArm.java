//This script looks for all existing functions, clears their code, and re-disassembles them, assuming that thumb mode is off.
//@category ARM
//@menupath Script.ARM.No-Thumbs ARM Disassembly
//@author Sam V

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
// Import some types we need to work with functions
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

// Import some types we need to work with programs

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DisassembleAllFunctionsInArm extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Greetings Mortals");
        if (currentProgram == null) {
            println("There is no program, only Zuul");
            return;
        }
        String programName;
        programName = currentProgram.getName();
        printf("Enumerating functions in %s.\n", programName);

        // currentProgram comes along with GhidraScript. You get it for free.
        // One of the functions for currentProgram is getFunctionManager(), which allows
        // you to interact with the functions in that program.
        FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
        scanAndRedo(functionIterator);

    }

    public void scanAndRedo(FunctionIterator functionIterator) {
        TaskMonitor taskMonitor = TaskMonitor.DUMMY;
        // Setting up the thumb mode register to be 0. See DoARMDisassemble.java.
        Register thumbModeRegister = currentProgram.getProgramContext().getRegister("TMode");

        // For every function in the function iterator, which contains all of the
        // functions
        // in the current program,

        // Initialize a HashMap to contain a mapping from addresses to functions
        TreeMap<Address, String> addressToFunctionMap = new TreeMap<Address, String>();
        for (Function currentFunction : functionIterator) {
            String functionName;
            functionName = currentFunction.getName();
            Address functionEntryPoint = currentFunction.getEntryPoint();

            // Fill the HashMap with the addresses and functions. Key by the function's
            // entrypoint.
            addressToFunctionMap.put(functionEntryPoint, functionName);

        }

        long maxDistance = 0;
        for (Map.Entry<Address, String> entry : addressToFunctionMap.entrySet()) {
            // Get a pair of addresses starting at the current function's entrypoint and
            // ending
            // at the entrypoint to the next function.
            Address functionEntryPoint = entry.getKey();
            Address nextFunctionEntrypoint = addressToFunctionMap.higherKey(functionEntryPoint);
            // For now ignore the very last function.
            if (nextFunctionEntrypoint == null) {
                break;
            }
            // Initialize the address we're looking at to the function entrypoint.
            // AddressSets are instantiated with the knowledge that a set of a addresses may
            // have multiple ranges.
            // We are working in the special case where each address set will have only one
            // address range.
            // Regardless, we have to play by the Ghidra API rules. Maybe there is a better
            // way to do this?
            List<AddressRange> potentialFunctionAddressSetList = new AddressSet(functionEntryPoint,
                    nextFunctionEntrypoint).toList();
            long distance = nextFunctionEntrypoint.subtract(functionEntryPoint);
            if (distance > maxDistance) {
                maxDistance = distance;
            }
            for (AddressRange currentAddressRange : potentialFunctionAddressSetList) {
                // Set up variables to contain the bounds of our newly created address range.
                Address addressRangeStart = currentAddressRange.getMinAddress();
                Address addressRangeEnd = currentAddressRange.getMaxAddress();
                // Attempt to clear everything between the start and end.
                try {
                    clearListing(addressRangeStart, addressRangeEnd);
                } catch (CancelledException e) {
                    e.printStackTrace();
                }

                // Now that thumb mode is turned off and the instructions over the range we're
                // looking at are cleared,
                // we can re-try disassembly with arm mode off.
                AddressSet addressSetViewForFunction = new AddressSet(currentProgram, addressRangeStart,
                        addressRangeEnd);
                // Signature:
                // ArmDisassembleCommand​(Address start, AddressSetView restrictedSet, boolean
                // thumbMode)
                ArmDisassembleCommand command = new ArmDisassembleCommand(addressRangeStart, addressSetViewForFunction,
                        false);
                // Signature:
                // applyTo​(DomainObject obj, TaskMonitor monitor)
                command.applyTo(currentProgram, taskMonitor);
                printf("%s at %s has been re-disassembled.\n", entry.getValue(), functionEntryPoint.toString());
            }
        }

        printf("Total function count: %d\n", addressToFunctionMap.keySet().size());
        printf("Max distance between functions: %d\n", maxDistance);
    }

}
