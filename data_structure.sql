
/*==============================================================*/
/* Table: applicationresultset                                  */
/*==============================================================*/
create table applicationresultset
(
   id           int not null auto_increment,
   type         int,  
   resultid     varchar(255),
   tcpfromid    int,
   primary key (id)
);

/*
                                    1  "email"
                                    2  "web"    
                                    3  "ftp"    FTP
                                    4  "msn"   MSN
                                    5  "QQnumber" QQnumber
                                    6  "cookies"  Cookies
                                    7  "UserandPassword" 
                                    8  "telnet"
*/

/*==============================================================*/
/* Table: attachment                                            */
/*==============================================================*/
create table attachment
(
   attachmentid         int not null auto_increment,
   filetype             text,
   filename             text,
   file                 longblob,
   emailid              varchar(255),
   primary key (attachmentid)
);

/*==============================================================*/
/* Table: email                                                  */
/*==============================================================*/
create table email
(
   id               varchar(255) not null,
   time             timestamp default CURRENT_TIMESTAMP,
   emailfrom             text,
   emailto               text,
   subject              text,
   content              blob,
   password             text,
   isattachment         int default 3,
   tcpid             int,
   optype            text,
   role              int, /*0-->recive  1--->send*/
   primary key (id)
);


/*=============================================================*/
/*Table: web                                                   */
/*=============================================================*/
create table web
(
    id          varchar(255) not null,
    time        timestamp default CURRENT_TIMESTAMP,
    tcpid       int,
    host	varchar(255),
    url         varchar(255),
    referer     varchar(255),
    access_time int,
    optype      varchar(255),
    haspostdata int,
    data_type   varchar(255),
    postdata    blob,
    srcip	varchar(255),
    dstip	varchar(255),
    primary key (id)
);


/*=============================================================*/
/*Table: cookies                                               */
/*=============================================================*/
create table cookies
(
    id         varchar(255) not null,
    time       timestamp default CURRENT_TIMESTAMP,
    tcpid      int,
    url        varchar(255),
    cookie     varchar(255),
    type       varchar(255),
    primary key (id)
);


/*==============================================================*/
/* Table: ftp                                                   */
/*==============================================================*/
create table ftp
(
   id                   varchar(255) not null,
   time                 timestamp default CURRENT_TIMESTAMP,
   tcpid                int,
   filetype             text,
   file                 longblob,
   filename             text,
   handle               text,
   ftpuser              text,
   ftppassword          text,
   primary key (id)
);

/*Table: telnet */

create table telnet
(
   id                   varchar(255) not null,
   time                 timestamp default CURRENT_TIMESTAMP,
   tcpid                int,
   content              text,
   password             text,
   command              text,
   primary key (id)
);


/*==============================================================*/
/* Table: msn                                                   */
/*==============================================================*/
create table msn
(
   id                   varchar(255) not null,
   time                 timestamp default CURRENT_TIMESTAMP,
   tcpid                int,
   send                 text,
   recieve              text,
   content              blob,
   file                 longblob,
   filesize             int,
   filename             text,
   access_time		int,
   primary key (id)
);

create table tcp
(
   tcpid                int not null auto_increment,
   desmac               text,
   srcmac               text,
   desip                text,
   srcip                text,
   desport              int,
   srcport              int,
   essid		varchar(255),
   bssid		varchar(255),
   timelast             timestamp default current_timestamp,
   primary key (tcpid)
);


/*==============================================================*/
/* Table: typeinformation                                       */
/*==============================================================*/
create table typeinformation
(
   typeid               int not null,
   typename             text,
   tcpport              text,
   udpport              text,
   istcp                int default 3,
   isudp                int default 3
);


/*==============================================================*/
/* Table: udp                                                   */
/*==============================================================*/
create table udp
(
   udpid                int not null auto_increment,
   packet               longblob,
   desmac               text,
   srcmac               text,
   desip                text,
   srcip                text,
   desport              int,
   srcport              int,
   timerecieve          timestamp default CURRENT_TIMESTAMP,
   primary key (udpid)
);
