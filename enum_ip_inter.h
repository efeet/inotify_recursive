struct numera_data{
        char  buf[1024];
        struct ifconf ifc;
        struct ifreq *ifr;
        int           sck;
        int           nInterfaces;
};

struct numera_data get_interfaces(void);

char * prt_interfaces(int i);