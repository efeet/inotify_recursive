#include "libraries_include.h"
#include "enum_ip_inter.h"

struct numera_data get_interfaces(void)
{
      struct numera_data data;
        data.sck = socket(AF_INET, SOCK_DGRAM, 0);
        if(data.sck < 0)
        {
                perror("Enum_IP&Interfaces");
                exit(1);
        }

        data.ifc.ifc_len = sizeof(data.buf);
        data.ifc.ifc_buf = data.buf;
        if(ioctl(data.sck, SIOCGIFCONF, &data.ifc) < 0)
        {
                perror("Enum_IP&Interfaces: ioctl(SIOCGIFCONF)");
                exit(1);
        }

        data.ifr         = data.ifc.ifc_req;
        data.nInterfaces = data.ifc.ifc_len / sizeof(struct ifreq);
	
	return data;
}

char * prt_interfaces(int i)
{
  static char buffer[1024]; 
  
  struct numera_data datafinal = get_interfaces();
  
        //for(i = 0; i < datafinal.nInterfaces; i++)
        //{
                struct ifreq *item = &datafinal.ifr[i];
		strcpy(buffer,inet_ntoa(((struct sockaddr_in *)&item->ifr_addr)->sin_addr));
                //buffer = inet_ntoa(((struct sockaddr_in *)&item->ifr_addr)->sin_addr);
        //}

        return (buffer == 0) ? NULL : buffer;
}


