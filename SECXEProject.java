//bassant yasser 19102749
//yara adel hassan mohamed 19100683
//task1 (done)read from file
// task2 (done) location counter format 2+3+4
//task3(done)object code format 2+3+4
//task4 (done)hte record 
package secxe.project;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
public class SECXEProject {
 static String Base;
    static ArrayList<String> ref = new ArrayList<String>();
    static ArrayList<String> label = new ArrayList<String>();
    static ArrayList<String> instr = new ArrayList<String>();
    static ArrayList<String> locctr = new ArrayList<String>();
    static ArrayList<String> ObjectCode = new ArrayList<String>();
    static ArrayList<ArrayList<String>> SymbolTable = new ArrayList<ArrayList<String>>();
    static HashMap<String, String> registers = new HashMap<String, String>();

    // a function for the opcodes of the secxe registers
    public static void InitializeRegisters() {
        //assigning these opcodes to the registers to be used when generating the object code
        registers.put("A", "0");
        registers.put("X", "1");
        registers.put("B", "3");
        registers.put("S", "4");
        registers.put("T", "5");
        registers.put("F", "6");
    }

    public static void CreateSymbolTable() {         //fn creates the symbol table to use it to generate the object code 
        int i = 0;
        int k = 0;
        while (!instr.get(i).equalsIgnoreCase("end")) {
            if (!label.get(i).matches("####")) {              //check if there is a label 
                SymbolTable.add(new ArrayList<String>());   //creating new list to put the label and the address 
                SymbolTable.get(k).add(0, label.get(i));    // putting each label in the symbol table 
                SymbolTable.get(k).add(1, locctr.get(i));   // putting the location beside its label
                k++;
            }
            i++;
        }
    }
    // checking if the input is a number or not

    public static boolean isNumeric(String str) {
        try {
            Double.parseDouble(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    //fn searches the symbol table to find the address of the refernce
    public static String SearchSymbol(String ref) {
        String address = null;
        boolean flag = false;      //to check if there was ,x in the reference     
        if (ref.startsWith("@") || ref.startsWith("#")) {
            ref = ref.substring(1);
        }
        for (int i = 0; i < SymbolTable.size(); i++) {
            char check = ref.charAt(ref.length() - 2);
            if (check == ',') {
                ref = ref.substring(0, ref.length() - 2); //we will remove the part ,x from the reference so we can find it in the symbol table 
                flag = true;
            }

            if (SymbolTable.get(i).get(0).matches(ref)) {
                if (flag) {
                    address = Integer.toHexString(32768 + Integer.parseInt(SymbolTable.get(i).get(1), 16)); //we will add 8000 to the address //convert to decimal to add then convert to hex 
                    flag = false;
                } else {
                    address = SymbolTable.get(i).get(1);         //getting the address directly from the symbol table 
                }
            }
        }
        return address;
    }

    //searching for  the opcode of the instruction
    public static String Search(String instr) {
        String opcode = "NOT FOUND";       //set the default to not found 
        NewClass obj = new NewClass();   //creating object of class converter
        NewClass.initialize();             //initializing the array of opcodes 
        String[][] OPTAB = obj.getArray();   //getting the array of  opcodes 
        if (instr.startsWith("+")) {
            instr = instr.substring(1, instr.length());
        }
        for (int i = 0; i < OPTAB.length; i++) {
            if (OPTAB[i][0].matches(instr)) {
                opcode = OPTAB[i][2];

            }
        }
        return opcode;
    }
    
    //a fun to determine the instruction is of which format (2,3,4) 
    public static String SearchFormat(String instr) {
        String format = "NOT FOUND";       //set the default to not found 
        NewClass obj = new NewClass();   //creating object of class converter
        NewClass.initialize();             //initializing the array of opcodes 
        String[][] OPTAB = obj.getArray();   //getting the array of  opcodes 
        if (instr.startsWith("+")) {
            instr = instr.substring(1, instr.length());
        }
        for (int i = 0; i < OPTAB.length; i++) {
            if (OPTAB[i][0].matches(instr)) {
                format = OPTAB[i][1];

            }
        }
        return format;
    }
    
    public static void readfile(){
        try {
            BufferedReader read = new BufferedReader(new FileReader("C:\\Users\\fast\\Downloads\\inSICXE.txt"));    //reading the file 
            String s;
            while ((s = read.readLine()) != null) {   //reading the file line by line 
                s = s.trim();
                String arr[] = s.split("\\s+");   //split the words by spaces

                if (arr.length == 3) {               //if there is three places "we didn't reach the end of file "
                    label.add(arr[0]);         //putting # instead of empty labels 
                    instr.add(arr[1]);
                    ref.add(arr[2]);

                } else if (arr.length == 2) {
                    label.add("####");
                    instr.add(arr[0]);
                    ref.add(arr[1]);
                } else if (arr.length == 1) {
                    label.add("####");
                    instr.add(arr[0]);
                    ref.add("####");
                }

            }
            read.close();
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        
    }
    
    public static void getlocation(){
        int j = 2;
        int k = 1;
        locctr.add(Integer.toHexString(0x10000 | Integer.parseInt(ref.get(0))).substring(1));
        locctr.add(Integer.toHexString(0x10000 | Integer.parseInt(ref.get(0))).substring(1));


        while (!instr.get(k).equalsIgnoreCase("End")) {  //looping till the end of the program 
            //handling special cases 

            if (instr.get(k).equalsIgnoreCase("RESW")) {
                locctr.add(Integer.toHexString(0x10000 | Integer.parseInt(locctr.get(k), 16) + (Integer.parseInt(ref.get(k))) * 3).substring(1));   //convert the previous add to decimal ,add it to the no of places *3 then generate the hexa location
            } else if (instr.get(k).equalsIgnoreCase("RESB")) {//convert the previous add to decimal ,add it to the no of places then generate the hexa location
                locctr.add(Integer.toHexString(0x10000 | Integer.parseInt(locctr.get(j - 1), 16) + (Integer.parseInt(ref.get(k)))).substring(1));
            } else if (instr.get(k).equalsIgnoreCase("BYTE")) {
                if (ref.get(k).startsWith("X")) {
                    locctr.add(Integer.toHexString(0x10000 | ((ref.get(k).length() - 3) / 2) + Integer.parseInt(locctr.get(j - 1), 16)).substring(1));  //convert the previous add to decimal ,add it to the no of digits /2 then generate the hexa location
                } else {
                    locctr.add(Integer.toHexString(0x10000 | ((ref.get(k).length() - 3)) + Integer.parseInt(locctr.get(j - 1), 16)).substring(1));  //convert the previous add to decimal ,add it to the no of places then generate the hexa location
                }
            } else if (instr.get(k).equalsIgnoreCase("word")) {
                locctr.add(Integer.toHexString(0x10000 | Integer.parseInt(locctr.get(j - 1), 16) + 3).substring(1));  //else add three to the previous loccation 
            } else {
                if (instr.get(k).startsWith("+")) {
                    locctr.add(Integer.toHexString(0x10000 | Integer.parseInt(locctr.get(j - 1), 16) + 4).substring(1));
                } else {
                    if (instr.get(k).equalsIgnoreCase("base")) {



                        locctr.add(locctr.get(k)); //else add three to the previous loccation 
                    } else {
                        String nn = "";       //set the default to not found 
                        NewClass obj = new NewClass();   //creating object of class converter
                        NewClass.initialize();             //initializing the array of opcodes 
                        String[][] OPTAB = obj.getArray();   //getting the array of  opcodes 
                        for (int i = 0; i < OPTAB.length; i++) {

                            if (OPTAB[i][0].equalsIgnoreCase(instr.get(k))) {

                                nn = OPTAB[i][1];
                                locctr.add(Integer.toHexString(0x10000 | Integer.parseInt(locctr.get(k), 16) + Integer.parseInt(nn)).substring(1));  //else add three to the previous loccation 
                            }

                        }
                    }
                }

            }
            j++;
            k++;
        }
        
    }
    
    public static void generateobjectcode(){
        int i;
        int no = 0;
        while (!instr.get(no).equalsIgnoreCase("End")) {  //loop till the end of the program 
            if (instr.get(no).equalsIgnoreCase("RESW") || instr.get(no).equalsIgnoreCase("RESB") || instr.get(no).equalsIgnoreCase("Start")) {
                ObjectCode.add("No object Code");   //no object code for those instructions 
            } else if (instr.get(no).equalsIgnoreCase("Byte")) {
                if (ref.get(no).startsWith("X")) {
                    ObjectCode.add(ref.get(no).substring(2, ref.get(no).length() - 1));  //we will put the hexa characters as it is 
                } else if (ref.get(no).startsWith("C")) {      //if it is characters we will get the ascii code of them 
                    String ascii = "";
                    String str = ref.get(no).substring(2, ref.get(no).length() - 1);
                    for (i = 0; i < str.length(); i++) {
                        int asciiValue = str.charAt(i);
                        ascii += (Integer.toHexString(asciiValue));  //concatenate  the ascii codes 
                    }
                    ObjectCode.add(ascii);
                }
            } else if (instr.get(no).equalsIgnoreCase("word")) {           //will convert the number to hexa and put it in six digits 
                int number = Integer.parseInt(ref.get(no));
                ObjectCode.add(Integer.toHexString(0x1000000 | number).substring(1));
            } else if (instr.get(no).equalsIgnoreCase("Base")) {
                ObjectCode.add("No object Code");
                Base = SearchSymbol(ref.get(no));
            } else if (instr.get(no).equalsIgnoreCase("rsub")) {
                ObjectCode.add("4f0000");

            } else if (!instr.get(no).startsWith("+")) {
                String n, m, x, b, p, e;
                String format = SearchFormat(instr.get(no));
                String opcode = Search(instr.get(no));

                String objectcode;
                if (format.equalsIgnoreCase("3")) {

                    if (ref.get(no).startsWith("#") & isNumeric(ref.get(no).substring(1))) {


                        n = "0";
                        m = "1";
                        x = "0";
                        b = "0";
                        p = "0";
                        e = "0";
                        String Displacement = Integer.toHexString(0x1000 | Integer.parseInt(ref.get(no).substring(1))).substring(1);
                        String part1 = Integer.toBinaryString(0x10 | Integer.parseInt(opcode.substring(0, opcode.length() - 1), 16)).substring(1);
                        String part2 = Integer.toBinaryString(0x10 | Integer.parseInt(opcode.substring(1, opcode.length()), 16)).substring(1);
                        String op = (part1 + part2).substring(0, (part1 + part2).length() - 2);
                        objectcode = op + n + m + x + b + p + e;


                        ObjectCode.add(Integer.toHexString(0x1000 | Integer.parseInt(objectcode, 2)).substring(1) + Displacement);



                    } else {
                     
                        String TA = SearchSymbol(ref.get(no));
                        n = "1";
                        m = "1";
                        x = "0";
                        b = "";
                        p = "";
                        e = "0";

                        if (ref.get(no).startsWith("@")) {
                            n = "1";
                            m = "0";

                        } else if (ref.get(no).startsWith("#") & !isNumeric(ref.get(no).substring(1))) {

                            n = "0";
                            m = "1";

                        }
                        if (ref.get(no).charAt(ref.get(no).length() - 2) == ',') {
                            x = "1";

                        }
                        // System.out.println(instr.get(no));
                        String Displacement = (Integer.toHexString(Integer.parseInt(TA, 16) - Integer.parseInt(locctr.get(no + 1), 16)));
                        if (-2048 < Long.valueOf(Displacement, 16).intValue() & Long.valueOf(Displacement, 16).intValue() < 2047) {
                            b = "0";
                            p = "1";


                        } else {
                            b = "1";
                            p = "0";
                            Displacement = (Integer.toHexString(Integer.parseInt(TA, 16) - Integer.parseInt(Base, 16)));
                        }

                        if (Displacement.length() > 3) {
                            Displacement = Displacement.substring(Displacement.length() - 3, Displacement.length());
                        }

                        Displacement = Integer.toHexString(0x1000 | Integer.parseInt(Displacement, 16)).substring(1);
                        String part1 = Integer.toBinaryString(0x10 | Integer.parseInt(opcode.substring(0, opcode.length() - 1), 16)).substring(1);
                        String part2 = Integer.toBinaryString(0x10 | Integer.parseInt(opcode.substring(1, opcode.length()), 16)).substring(1);
                        String op = (part1 + part2).substring(0, (part1 + part2).length() - 2);
                        objectcode = op + n + m + x + b + p + e;

                        ObjectCode.add(Integer.toHexString(0x1000 | Integer.parseInt(objectcode, 2)).substring(1) + Displacement);


                    }


                } ///////////////////FORMAT 2
                else {
                    String objcode = Search(instr.get(no));
                    String arrRegister[] = ref.get(no).split(",");
                    if (arrRegister.length == 2) {
                        objcode += registers.get(arrRegister[0]);
                        objcode += registers.get(arrRegister[1]);

                    } else if (arrRegister.length == 1) {
                        objcode += registers.get(arrRegister[0]);
                        objcode += "0";

                    }
                    ObjectCode.add(objcode);

                    ////////////////////////////////////////
                }

            } else if (instr.get(no).startsWith("+")) {
                String n, I, x, p, b, e;
                n = "1";
                I = "1";
                x = "0";
                b = "0";
                p = "0";
                e = "1";
                String opcode = Search(instr.get(no));
                String part1 = Integer.toBinaryString(0x10 | Integer.parseInt(opcode.substring(0, opcode.length() - 1), 16)).substring(1);
                String part2 = Integer.toBinaryString(0x10 | Integer.parseInt(opcode.substring(1, opcode.length()), 16)).substring(1);
                String op = (part1 + part2).substring(0, (part1 + part2).length() - 2);
                String address;
                if (ref.get(no).startsWith("#") && isNumeric(ref.get(no).substring(1))) {
                    n = "0";
                    I = "1";
                    address = Integer.toHexString(0x100000 | Integer.parseInt(ref.get(no).substring(1))).substring(1);
                    String objectcode = op + n + I + x + b + p + e;
                    ObjectCode.add(Integer.toHexString(0x1000 | Integer.parseInt(objectcode, 2)).substring(1) + address);
                } else {


                    if (ref.get(no).startsWith("@")) {
                        n = "1";
                        I = "0";
                    } else if (ref.get(no).startsWith("#") && !isNumeric(ref.get(no).substring(1))) {
                        n = "0";
                        I = "1";
                    }
                    String objectcode = op + n + I + x + b + p + e;
                    address = Integer.toHexString(0x100000 | Integer.parseInt(SearchSymbol(ref.get(no)), 16)).substring(1);
                    ObjectCode.add(Integer.toHexString(0x1000 | Integer.parseInt(objectcode, 2)).substring(1) + address);
                }
            }



            no++;
        }
        if (instr.get(no).equalsIgnoreCase("End")) {
            ObjectCode.add("No object Code");
        }
        
    }
 
    public static void HTErecord(){
        int i;
        ArrayList<String> H = new ArrayList<String>();
        ArrayList<String> E = new ArrayList<String>();
        int num = Integer.parseInt(locctr.get(locctr.size() - 1), 16) - Integer.parseInt(locctr.get(0), 16);  //getting the length of the program 
        String progName = label.get(0);
        while (progName.length() < 6) {
            progName = "X" + progName;    //add x if the program name takes less than 6 digits 
        }
        H.add("H");
        H.add(progName);
        H.add(Integer.toHexString(0x1000000 | Integer.parseInt(locctr.get(0), 16)).substring(1));  //adding the starting address of the program in 6 digits 
        H.add(Integer.toHexString(0x1000000 | num).substring(1));  //adding the length  of the program in 6 digits 
        E.add("E");
        E.add(Integer.toHexString(0x1000000 | Integer.parseInt(locctr.get(0), 16)).substring(1)); //adding the start address of the program 
        System.out.println(H);
        int z = 0;
        
        List<ArrayList<String>> listOfLists = new ArrayList<ArrayList<String>>(); //creating list of lists for the T record 
        while (!instr.get(z).equalsIgnoreCase("end")) {  //loop till the end of the program 
            ArrayList<String> list1 = new ArrayList<String>(); //creating new T record 
            if( ! ObjectCode.get(z).equalsIgnoreCase("No object Code")){
            list1.add("T") ; 
             list1.add( Integer.toHexString( 0x1000000 | Integer.parseInt(locctr.get(z), 16)).substring(1));
          
            }
            int size = 1;
            while (size < 30 && !instr.get(z).equalsIgnoreCase("start") && !instr.get(z).equalsIgnoreCase("end") && !instr.get(z).equalsIgnoreCase("resb")
                && !instr.get(z).equalsIgnoreCase("resw")) {
                if (instr.get(z).equalsIgnoreCase("Base")) {
                    z++;;

                } else {
                    list1.add(ObjectCode.get(z));
                    
                    size += ObjectCode.get(z).length() /2;   //calcaulating the size of the T record 
                   
                    z++;
                }
                
            }
            if (ObjectCode.get(z).equalsIgnoreCase("No object Code")) {
                if (!instr.get(z).equalsIgnoreCase("end")) {
                    size = 0;
                    z++;
                }
            } else {
                size = 0;    //not incresing z not to lose the exsiting object code after exiting the while loop

            }
            if (!list1.isEmpty()) {  //incase creating list and the first instr was RESW /RESB 
                listOfLists.add(list1);
              
            }
        }
        int length = 0;
        for (int loop = 0; loop < listOfLists.size(); loop++) {
            for (int l = 2; l < listOfLists.get(loop).size(); l++) {
                length += (listOfLists.get(loop).get(l).length()) / 2; //getting the length of T record 
            }
            listOfLists.get(loop).add(2, Integer.toHexString ( 0x100 | length).substring(1));
            length = 0;
        }
      
     
        for (i = 0; i < listOfLists.size(); i++) {
            System.out.println(listOfLists.get(i));
        }

        System.out.println(E);
        
    }
    
    

    public static void main(String[] args) {
        
        readfile();
        InitializeRegisters();
        getlocation();
        CreateSymbolTable();
        generateobjectcode();
        
        
        int i;
        System.out.println("===================================================================================================");
        System.out.println("SECXE FILE:");
        for (i = 0; i < label.size(); i++) {

            System.out.print(locctr.get(i) + "    ");
            System.out.print(label.get(i) + "    ");
            System.out.print(instr.get(i) + "    ");
            System.out.print(ref.get(i) + "    ");
            System.out.println(ObjectCode.get(i) + "    ");
        }
        System.out.println("===================================================================================================");
        System.out.println("symbol table:");
        for( i=0; i<SymbolTable.size(); i++)
        {
            System.out.println(SymbolTable.get(i));
        }
       
        System.out.println("===================================================================================================");
        System.out.println("HTE Record:");
        HTErecord();
        System.out.println("===================================================================================================");
        
    } 

    }