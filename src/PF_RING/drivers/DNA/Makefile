#
# IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT
#
# When you change the versions below also update
#  - ~/PF_RING/PF_RING/package/ubuntu/Makefile
#  - ~/PF_RING/package/rpm/pfring.spec

E1000=e1000-8.0.35
E1000E=e1000e-2.0.0.1
IGB=igb-3.4.7
IXGBE=ixgbe-3.18.7

all: igb ixgbe e1000e #e1000

e1000:
	cd $(E1000)-DNA/src; make

e1000e:
	cd $(E1000E)-DNA/src; make

igb:
	cd $(IGB)-DNA/src; make

ixgbe:
	cd $(IXGBE)-DNA/src; make

clean:
	cd $(E1000)-DNA/src; make clean
	cd $(E1000E)-DNA/src; make clean
	cd $(IGB)-DNA/src; make clean
	cd $(IXGBE)-DNA/src; make clean

