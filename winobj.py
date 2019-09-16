# WinObj.py
# Author: Shachaf Atun (KSL group)
# Email: ksl.taskforce@gmail.com
# Description:
# WinObj plugin helps you map the Object Manager.
# Similar to the winObj.exe tool from sysinternals (https://docs.microsoft.com/en-us/sysinternals/downloads/winobj),
# With additional information about every object you may find.
# WinObj can help you enumreate every directory you need such as: KnwonDlls,ObjectTypes,Sessions,BaseNamedObjects etc,
# And find suspicious objects within these directories.
# For full documentation and usage: https://github.com/kslgroup/WinObj


# Imports
import volatility.obj as Obj
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks


#Globals
NAME                            = 0x1
ADDR                            = 0x0
HEADER                          = 0x2
VALUES                          = 0x1
ADDITIONAL_INFO                 = 0x3


class WinObj(taskmods.DllList):
    """
     Object Manager Enumeration
    """

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option('PARSE-ALL', short_option='A', default=False,
                          action='store_true', help='Parse every directory under the root dir')
        config.add_option("SUPPLY-ADDR",short_option='a', type=str,
                          help = "Parse directories under specific addresses")
        config.add_option("FULL-PATH",short_option='P', type=str,
                          help = "Parse a directory found by full path location")

        self.root_obj_list = []
        self.tables = {}

        # Sets default values of a 64 bit machine,
        #the values will be updated according to the profile
        self.POINTER_SIZE                    = 0x8
        self.OBJECT_HEADER_QUOTA_INFO_SIZE   = 0x20
        self.OBJECT_HEADER_PROCESS_INFO_SIZE = 0x10
        self.OBJECT_HEADER_HANDLE_INFO_SIZE  = 0x10
        self.OBJECT_HEADER_NAME_INFO_SIZE    = 0x20
        self.OBJECT_HEADER_CREATOR_INFO_SIZE = 0x20
        self.OBJECT_HEADER_NAME_INFO_ID      = 0x2
        self.OBJECT_HEADER_CREATOR_INFO_ID   = 0x1
        self.OBJECT_HEADER_HANDLE_INFO_ID    = 0x4
        self.OBJECT_HEADER_QUOTA_INFO_ID     = 0x8
        self.OBJECT_HEADER_PROCESS_INFO_ID   = 0x10
        self.OBJECT_HEADER_SIZE              = 0x30
        self.OBJECT_POOL_HEADER              = 0x10
        self.OBJECT_INFO_HEADERS_LIST        = [self.OBJECT_HEADER_CREATOR_INFO_ID,
                                                 self.OBJECT_HEADER_HANDLE_INFO_ID,
                                                 self.OBJECT_HEADER_QUOTA_INFO_ID,
                                                 self.OBJECT_HEADER_NAME_INFO_ID,
                                                 self.OBJECT_HEADER_PROCESS_INFO_ID]

        self.OBJECT_INFO_HEADERS_ID_TO_SIZE  ={self.OBJECT_HEADER_NAME_INFO_ID: self.OBJECT_HEADER_NAME_INFO_SIZE,
                                               self.OBJECT_HEADER_CREATOR_INFO_ID: self.OBJECT_HEADER_CREATOR_INFO_SIZE,
                                               self.OBJECT_HEADER_HANDLE_INFO_ID : self.OBJECT_HEADER_HANDLE_INFO_SIZE,
                                               self.OBJECT_HEADER_QUOTA_INFO_ID : self.OBJECT_HEADER_QUOTA_INFO_SIZE,
                                               self.OBJECT_HEADER_PROCESS_INFO_ID: self.OBJECT_HEADER_PROCESS_INFO_SIZE}


    def get_root_directory(self,kdbg,addr_space):
        """
     
        :param kdbg      : kdbg object
        :param addr_space: kernel address space
        :return          : a pointer to the root directory

        """
        # gets the pointer from the kdbg sturcture
        root_dir_addr = Obj.Object("Pointer",kdbg.ObpRootDirectoryObject,vm=addr_space)
        return root_dir_addr

  
    def update_sizes(self,addr_space):
        """
        :param addr_space: kernel address space
        :return          : None

        the function will update the sizes of the vtype objects according to their sizes from the selected profile

        """  
        # updates pointer size
        self.POINTER_SIZE = addr_space.profile.get_obj_size("Pointer")

        # gets the vtypes from the profile
        profile_vtypes = addr_space.profile.vtypes

        # checks if the profile has the structure
        if profile_vtypes.has_key("_OBJECT_HEADER_QUOTA_INFO"):
            self.OBJECT_HEADER_QUOTA_INFO_SIZE   = addr_space.profile.get_obj_size("_OBJECT_HEADER_QUOTA_INFO")
        else:
             self.OBJECT_HEADER_QUOTA_INFO_SIZE = 0x0

        # checks if the profile has the structure
        if profile_vtypes.has_key("_OBJECT_HEADER_PROCESS_INFO"):
            self.OBJECT_HEADER_PROCESS_INFO_SIZE = addr_space.profile.get_obj_size("_OBJECT_HEADER_PROCESS_INFO")
        else:
            self.OBJECT_HEADER_PROCESS_INFO_SIZE = 0x0

        # checks if the profile has the structure
        if profile_vtypes.has_key("_OBJECT_HEADER_HANDLE_INFO"):
            self.OBJECT_HEADER_HANDLE_INFO_SIZE  = addr_space.profile.get_obj_size("_OBJECT_HEADER_HANDLE_INFO")
        else:
            self.OBJECT_HEADER_HANDLE_INFO_SIZE  = 0

        # checks if the profile has the structure
        if profile_vtypes.has_key("_OBJECT_HEADER_CREATOR_INFO"):
            self.OBJECT_HEADER_CREATOR_INFO_SIZE = addr_space.profile.get_obj_size("_OBJECT_HEADER_CREATOR_INFO")
        else:
            self.OBJECT_HEADER_CREATOR_INFO_SIZE = 0x0
        
        self.OBJECT_HEADER_NAME_INFO_SIZE    = addr_space.profile.get_obj_size("_OBJECT_HEADER_NAME_INFO")

        # subtract 0x8 from the size to remove the body itself
        self.OBJECT_HEADER_SIZE              = addr_space.profile.get_obj_size("_OBJECT_HEADER") -0x8
   

    def get_all_object_headers(self,mask):
        """
        :param mask: InfoMask from the object header
        :return    : list

        the function will return all the info headers that present in the object

        """ 
        present_info_headers = []

        for info_id in self.OBJECT_INFO_HEADERS_LIST:

            # checks if the header presents
            if mask & info_id != 0:
                present_info_headers.append(info_id)
            
        return present_info_headers



    def get_additional_info(self,myObj,addr_space,obj_type,obj_header):
        """
        :param myObj     : pointer object 
        :param addr_space: kernel address space
        :param obj_type  : string of the type
        :param obj_header: "_OBJECT_HEADER"
        :return          : list

        the function will return additional information about the object

        """ 
        # additional information about SymbolicLink
        if obj_type == "SymbolicLink":
            myObj = myObj.dereference_as("_OBJECT_SYMBOLIC_LINK")
            return "Target: {}".format(myObj.LinkTarget)

        # additional information about Section    
        elif obj_type == "Section":
            myObj = myObj.dereference_as("_SECTION_OBJECT")

            # the default is "_SEGMENT_OBJECT", and we need _SEGMENT
            filePointer = myObj.Segment.dereference_as("_SEGMENT").ControlArea.FilePointer
            

            # checks if this is a new version
            if filePointer.obj_type:
                FileObj = Obj.Object("_FILE_OBJECT",filePointer.Object-filePointer.RefCnt,vm=addr_space)

            # old version
            else:
                FileObj = filePointer
            
            return "FileObj: {}".format(FileObj.FileName.v())
        
        # additional information about Driver
        elif obj_type == "Driver":
            driver = myObj.dereference_as("_DRIVER_OBJECT")
            return "Full Name: {}".format(driver.DriverName.v())

        # additional information about Device
        elif obj_type == "Device":
            device = myObj.dereference_as("_DEVICE_OBJECT")
            return "Driver: {}".format(device.DriverObject.DriverName.v())

        # additional information about Type
        elif obj_type == "Type":
            myType = myObj.dereference_as("_OBJECT_TYPE")
            return "Key: {}".format(myType.Key)


        # additional information about Window Station
        elif obj_type == "WindowStation":
            win_sta = myObj.dereference_as("tagWINDOWSTATION")
            names = "".join("{} ".format(Desktop.Name) for Desktop in win_sta.desktops()).strip()
            session_id = win_sta.dwSessionId
            atom_table = hex(win_sta.pGlobalAtomTable)[:-1]
            return "Desktop Names:{},Session Id:{},Atoms:{}".format(names,session_id,atom_table)
        
        # additional information about all the others
        else:
            return "Hnadle Count - {}, Pointer Count {}".format(obj_header.HandleCount,obj_header.PointerCount)


    def GetName(self,obj_header,addr_space):
        """
        :param obj_header: "_OBJECT_HEADER"
        :param addr_space: kernel address space
        :return          : string

        the function will return the name of the object

        """
        # checks if this is an old version
        if addr_space.profile.obj_has_member("_OBJECT_HEADER","NameInfoOffset"):
            size = obj_header.NameInfoOffset
            
        # new version
        else:
            info_headers = self.get_all_object_headers(obj_header.InfoMask)

            # calculates the size according to the info headers
            if self.OBJECT_HEADER_CREATOR_INFO_ID in info_headers:
                size = self.OBJECT_HEADER_NAME_INFO_SIZE + self.OBJECT_HEADER_CREATOR_INFO_SIZE
            else:
                size = self.OBJECT_HEADER_NAME_INFO_SIZE
        
        name_info = Obj.Object("_OBJECT_HEADER_NAME_INFO",obj_header.v()-size,addr_space)   

        # checks that the name is not empty
        if name_info.Name:

            # validates the name
            if name_info.Name.Buffer and name_info.Name.Length <= name_info.Name.MaximumLength:
                #return name_info.Name
                return addr_space.read(name_info.Name.Buffer,
                                  name_info.Name.Length).replace("\x00", '')

        return ""


    
    def AddToList(self,myObj,addr_space,l):
        """
        :param myObj     : pointer object 
        :param addr_space: kernel address space
        :param l         : list

        :return          : None

        the function will add the object to the received list after a validation

        """   
        obj_header = Obj.Object("_OBJECT_HEADER",myObj.v()-self.OBJECT_HEADER_SIZE,addr_space)
        name = self.GetName(obj_header,addr_space)

        # validates the object
        if name:
            add_info = self.get_additional_info(myObj,addr_space,obj_header.get_object_type(),obj_header)
            l.append((myObj,name,obj_header,add_info))

                               
                
     
    def get_array(self,addr,addr_space):
        """
        :param addr      : long, pointer the the driectory
        :param addr_space: kernel address space
        

        :return          : Array object

        the function will return a the directory, after a size calculation

        """

        # min value for the array
        count = 2

        # searches the directory size
        while True:
            test_directory_array = Obj.Object("Array", targetType="Pointer", offset=addr, count=count,vm=addr_space)

            # parse until signal
            if (test_directory_array[-1].v() == 0xffffffff): 
                return test_directory_array
            else:
                
                count +=1


    def parse_directory(self,addr,addr_space,l):
        """
        :param addr      : long, pointer the the driectory
        :param addr_space: kernel address space
        :param l         : list

        :return          : None

        the function will parse the directory and add every valid object to the received list

        """   
        directory_array = self.get_array(addr,addr_space)
        
        for pointer_addr in directory_array:
            myObj = Obj.Object("Pointer",pointer_addr+self.POINTER_SIZE,vm=addr_space)

            # obj is not a null pointer
            if myObj:
                self.AddToList(myObj,addr_space,l)

            extra = Obj.Object("Pointer",pointer_addr,vm=addr_space)
            extra1 = Obj.Object("Pointer",extra+self.POINTER_SIZE,vm=addr_space)
            extra = Obj.Object("Pointer",extra,vm=addr_space)
            extra2 = Obj.Object("Pointer",extra+self.POINTER_SIZE,vm=addr_space)

            # extra1 is not a null pointer
            if extra1:
                    self.AddToList(extra1,addr_space,l)
                    
            # extra2 is not a null pointer        
            if extra2:
                    self.AddToList(extra2,addr_space,l)
                        


    def get_directory(self,addr_space,name="",root_dir=[]):
        """
        :param addr_space: kernel address space
        :param name      : string
        :param root_dir  : list of tuples
        :return          : None

        the function will parse the root directory object and add every directory/given name,
        to the tables dictionary

        """
        l = []
        name = str(name)

        # checks whether a root dir was given or not
        if not root_dir:

            # default option
            root_dir = self.root_obj_list
            
        # parses the root directory
        for obj,obj_name,obj_header,add_info in root_dir:

            # if there is a specific name
            if name:
                
                # if this is the name that was received
                if name.lower() == obj_name.lower():
                    self.parse_directory(obj.v(),addr_space,l)
                    self.tables[obj_name] = (obj.v(),l)
                    break
                
            # parse all
            else:

                # checks if object is a directory
                if obj_header.get_object_type() == "Directory":
                    self.parse_directory(obj.v(),addr_space,l)
                    self.tables[obj_name] = (obj.v(),l)
                    l = []

    def SaveByPath(self,path,addr_space):
        # validation
        try:

            # takes a copy in order to remove all stages from the final parser
            save = self.tables.copy()

            stages = path.split("/")[1:]

            # allow backslashes as well
            if len(stages) == 0:
                stages = path.split("\\")[1:]
                
            self.get_directory(addr_space,stages[0])


            addr,current_dir = self.tables[stages[0]]
                
            
            for place,stage in enumerate(stages[1:]):
                self.get_directory(addr_space,stage,current_dir)
                addr,current_dir = self.tables[stage]

            # removes all stages
            save_list = current_dir
            self.tables = save

            #sets the full path in the dictionary
            self.tables[path] = (addr,current_dir)

        except KeyError, er:
            raise KeyError("Invalid Path -> {}".format(path))

      
    def calculate(self):

        # gets the kernel address space
        addr_space = utils.load_as(self._config)

        # updates vtype objects' size
        self.update_sizes(addr_space)

        kdbg = tasks.get_kdbg(addr_space)
        root_dir = self.get_root_directory(kdbg,addr_space)
        self.parse_directory(root_dir,addr_space,self.root_obj_list)

        # checks for the SUPPLY_ADDR option
        if self._config.SUPPLY_ADDR:
            addrs = self._config.SUPPLY_ADDR.split(",")
            for addr in addrs:
                l = []

                # validates the address
                try:
                    addr = eval(addr)

                # addr is not valid
                except (SyntaxError,NameError):
                    continue

                obj_header = Obj.Object("_OBJECT_HEADER",addr-self.OBJECT_HEADER_SIZE,addr_space)
                name = self.GetName(obj_header,addr_space)

                # validates the directory
                if name:
                    self.parse_directory(addr,addr_space,l)
                    self.tables[name] = (addr,l)

        # checks for the FULL_PATH option
        elif self._config.FULL_PATH:

            # gets all dirs
            dirs = self._config.FULL_PATH.split(",")
            for path in dirs:
                self.SaveByPath(path,addr_space)

        # default option
        else:
            self.tables["/"] = (root_dir,self.root_obj_list)

            # checks for the PARSE_ALL option
            if self._config.PARSE_ALL:
                self.get_directory(addr_space)
    
        
    def render_text(self, outfd, data):
    
        outfd.write("\nWinObj Parser:\n")
        outfd.write("----------------------\n\n")
        
        
        for table in self.tables:
            outfd.write("\nParsing Now -> {} at {}\n\n".format(table,hex(self.tables[table][ADDR])[:-1]))
            l = self.tables[table][VALUES]
            self.table_header(outfd, [('Object Address(V)', '[addrpad]'),
                                      ('Name', '50'),
                                      ('Type', '20'),
                                      ("Additional Info","80"),])
            for obj in l:  
                self.table_row(outfd,
                                obj[ADDR],
                                obj[NAME],
                                obj[HEADER].get_object_type(),
                                obj[ADDITIONAL_INFO])
            
            outfd.write("*"*170)
                    
