package internal

import (
	"math/rand"
	"testing"
)

func BenchmarkSwitchCaseVsMap(b *testing.B) {
	events := generateRandomEvents(1000_000)
	b.Run("SwitchCase", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			switchCase(events[i%1000_000])
		}
	})
	b.Run("FuncMap", func(b *testing.B) {
		handlers := map[int]func(int){
			1:   testHandler1,
			2:   testHandler2,
			3:   testHandler3,
			4:   testHandler4,
			5:   testHandler5,
			6:   testHandler6,
			7:   testHandler7,
			8:   testHandler8,
			9:   testHandler9,
			10:  testHandler10,
			11:  testHandler11,
			12:  testHandler12,
			13:  testHandler13,
			14:  testHandler14,
			15:  testHandler15,
			16:  testHandler16,
			17:  testHandler17,
			18:  testHandler18,
			19:  testHandler19,
			20:  testHandler20,
			21:  testHandler21,
			22:  testHandler22,
			23:  testHandler23,
			24:  testHandler24,
			25:  testHandler25,
			26:  testHandler26,
			27:  testHandler27,
			28:  testHandler28,
			29:  testHandler29,
			30:  testHandler30,
			31:  testHandler31,
			32:  testHandler32,
			33:  testHandler33,
			34:  testHandler34,
			35:  testHandler35,
			36:  testHandler36,
			37:  testHandler37,
			38:  testHandler38,
			39:  testHandler39,
			40:  testHandler40,
			41:  testHandler41,
			42:  testHandler42,
			43:  testHandler43,
			44:  testHandler44,
			45:  testHandler45,
			46:  testHandler46,
			47:  testHandler47,
			48:  testHandler48,
			49:  testHandler49,
			50:  testHandler50,
			51:  testHandler51,
			52:  testHandler52,
			53:  testHandler53,
			54:  testHandler54,
			55:  testHandler55,
			56:  testHandler56,
			57:  testHandler57,
			58:  testHandler58,
			59:  testHandler59,
			60:  testHandler60,
			61:  testHandler61,
			62:  testHandler62,
			63:  testHandler63,
			64:  testHandler64,
			65:  testHandler65,
			66:  testHandler66,
			67:  testHandler67,
			68:  testHandler68,
			69:  testHandler69,
			70:  testHandler70,
			71:  testHandler71,
			72:  testHandler72,
			73:  testHandler73,
			74:  testHandler74,
			75:  testHandler75,
			76:  testHandler76,
			77:  testHandler77,
			78:  testHandler78,
			79:  testHandler79,
			80:  testHandler80,
			81:  testHandler81,
			82:  testHandler82,
			83:  testHandler83,
			84:  testHandler84,
			85:  testHandler85,
			86:  testHandler86,
			87:  testHandler87,
			88:  testHandler88,
			89:  testHandler89,
			90:  testHandler90,
			91:  testHandler91,
			92:  testHandler92,
			93:  testHandler93,
			94:  testHandler94,
			95:  testHandler95,
			96:  testHandler96,
			97:  testHandler97,
			98:  testHandler98,
			99:  testHandler99,
			100: testHandler100,
		}
		for i := 0; i < b.N; i++ {
			ind := i % 1000_000
			if handler, ok := handlers[events[ind]]; ok {
				handler(events[ind])
			}
		}
	})
}

func generateRandomEvents(n int) []int {
	events := make([]int, n)
	for i := 0; i < n; i++ {
		events[i] = rand.Intn(20) + 1 // Assuming event types are from 1 to 20
	}
	return events
}

func switchCase(foo int) {
	switch foo {
	case 1:
		testHandler1(foo)
	case 2:
		testHandler2(foo)
	case 3:
		testHandler3(foo)
	case 4:
		testHandler4(foo)
	case 5:
		testHandler5(foo)
	case 6:
		testHandler6(foo)
	case 7:
		testHandler7(foo)
	case 8:
		testHandler8(foo)
	case 9:
		testHandler9(foo)
	case 10:
		testHandler10(foo)
	case 11:
		testHandler11(foo)
	case 12:
		testHandler12(foo)
	case 13:
		testHandler13(foo)
	case 14:
		testHandler14(foo)
	case 15:
		testHandler15(foo)
	case 16:
		testHandler16(foo)
	case 17:
		testHandler17(foo)
	case 18:
		testHandler18(foo)
	case 19:
		testHandler19(foo)
	case 20:
		testHandler20(foo)
	case 21:
		testHandler21(foo)
	case 22:
		testHandler22(foo)
	case 23:
		testHandler23(foo)
	case 24:
		testHandler24(foo)
	case 25:
		testHandler25(foo)
	case 26:
		testHandler26(foo)
	case 27:
		testHandler27(foo)
	case 28:
		testHandler28(foo)
	case 29:
		testHandler29(foo)
	case 30:
		testHandler30(foo)
	case 31:
		testHandler31(foo)
	case 32:
		testHandler32(foo)
	case 33:
		testHandler33(foo)
	case 34:
		testHandler34(foo)
	case 35:
		testHandler35(foo)
	case 36:
		testHandler36(foo)
	case 37:
		testHandler37(foo)
	case 38:
		testHandler38(foo)
	case 39:
		testHandler39(foo)
	case 40:
		testHandler40(foo)
	case 41:
		testHandler41(foo)
	case 42:
		testHandler42(foo)
	case 43:
		testHandler43(foo)
	case 44:
		testHandler44(foo)
	case 45:
		testHandler45(foo)
	case 46:
		testHandler46(foo)
	case 47:
		testHandler47(foo)
	case 48:
		testHandler48(foo)
	case 49:
		testHandler49(foo)
	case 50:
		testHandler50(foo)
	case 51:
		testHandler51(foo)
	case 52:
		testHandler52(foo)
	case 53:
		testHandler53(foo)
	case 54:
		testHandler54(foo)
	case 55:
		testHandler55(foo)
	case 56:
		testHandler56(foo)
	case 57:
		testHandler57(foo)
	case 58:
		testHandler58(foo)
	case 59:
		testHandler59(foo)
	case 60:
		testHandler60(foo)
	case 61:
		testHandler61(foo)
	case 62:
		testHandler62(foo)
	case 63:
		testHandler63(foo)
	case 64:
		testHandler64(foo)
	case 65:
		testHandler65(foo)
	case 66:
		testHandler66(foo)
	case 67:
		testHandler67(foo)
	case 68:
		testHandler68(foo)
	case 69:
		testHandler69(foo)
	case 70:
		testHandler70(foo)
	case 71:
		testHandler71(foo)
	case 72:
		testHandler72(foo)
	case 73:
		testHandler73(foo)
	case 74:
		testHandler74(foo)
	case 75:
		testHandler75(foo)
	case 76:
		testHandler76(foo)
	case 77:
		testHandler77(foo)
	case 78:
		testHandler78(foo)
	case 79:
		testHandler79(foo)
	case 80:
		testHandler80(foo)
	case 81:
		testHandler81(foo)
	case 82:
		testHandler82(foo)
	case 83:
		testHandler83(foo)
	case 84:
		testHandler84(foo)
	case 85:
		testHandler85(foo)
	case 86:
		testHandler86(foo)
	case 87:
		testHandler87(foo)
	case 88:
		testHandler88(foo)
	case 89:
		testHandler89(foo)
	case 90:
		testHandler90(foo)
	case 91:
		testHandler91(foo)
	case 92:
		testHandler92(foo)
	case 93:
		testHandler93(foo)
	case 94:
		testHandler94(foo)
	case 95:
		testHandler95(foo)
	case 96:
		testHandler96(foo)
	case 97:
		testHandler97(foo)
	case 98:
		testHandler98(foo)
	case 99:
		testHandler99(foo)
	case 100:
		testHandler100(foo)
	}
}

func testHandler1(foo int)   {}
func testHandler2(foo int)   {}
func testHandler3(foo int)   {}
func testHandler4(foo int)   {}
func testHandler5(foo int)   {}
func testHandler6(foo int)   {}
func testHandler7(foo int)   {}
func testHandler8(foo int)   {}
func testHandler9(foo int)   {}
func testHandler10(foo int)  {}
func testHandler11(foo int)  {}
func testHandler12(foo int)  {}
func testHandler13(foo int)  {}
func testHandler14(foo int)  {}
func testHandler15(foo int)  {}
func testHandler16(foo int)  {}
func testHandler17(foo int)  {}
func testHandler18(foo int)  {}
func testHandler19(foo int)  {}
func testHandler20(foo int)  {}
func testHandler21(foo int)  {}
func testHandler22(foo int)  {}
func testHandler23(foo int)  {}
func testHandler24(foo int)  {}
func testHandler25(foo int)  {}
func testHandler26(foo int)  {}
func testHandler27(foo int)  {}
func testHandler28(foo int)  {}
func testHandler29(foo int)  {}
func testHandler30(foo int)  {}
func testHandler31(foo int)  {}
func testHandler32(foo int)  {}
func testHandler33(foo int)  {}
func testHandler34(foo int)  {}
func testHandler35(foo int)  {}
func testHandler36(foo int)  {}
func testHandler37(foo int)  {}
func testHandler38(foo int)  {}
func testHandler39(foo int)  {}
func testHandler40(foo int)  {}
func testHandler41(foo int)  {}
func testHandler42(foo int)  {}
func testHandler43(foo int)  {}
func testHandler44(foo int)  {}
func testHandler45(foo int)  {}
func testHandler46(foo int)  {}
func testHandler47(foo int)  {}
func testHandler48(foo int)  {}
func testHandler49(foo int)  {}
func testHandler50(foo int)  {}
func testHandler51(foo int)  {}
func testHandler52(foo int)  {}
func testHandler53(foo int)  {}
func testHandler54(foo int)  {}
func testHandler55(foo int)  {}
func testHandler56(foo int)  {}
func testHandler57(foo int)  {}
func testHandler58(foo int)  {}
func testHandler59(foo int)  {}
func testHandler60(foo int)  {}
func testHandler61(foo int)  {}
func testHandler62(foo int)  {}
func testHandler63(foo int)  {}
func testHandler64(foo int)  {}
func testHandler65(foo int)  {}
func testHandler66(foo int)  {}
func testHandler67(foo int)  {}
func testHandler68(foo int)  {}
func testHandler69(foo int)  {}
func testHandler70(foo int)  {}
func testHandler71(foo int)  {}
func testHandler72(foo int)  {}
func testHandler73(foo int)  {}
func testHandler74(foo int)  {}
func testHandler75(foo int)  {}
func testHandler76(foo int)  {}
func testHandler77(foo int)  {}
func testHandler78(foo int)  {}
func testHandler79(foo int)  {}
func testHandler80(foo int)  {}
func testHandler81(foo int)  {}
func testHandler82(foo int)  {}
func testHandler83(foo int)  {}
func testHandler84(foo int)  {}
func testHandler85(foo int)  {}
func testHandler86(foo int)  {}
func testHandler87(foo int)  {}
func testHandler88(foo int)  {}
func testHandler89(foo int)  {}
func testHandler90(foo int)  {}
func testHandler91(foo int)  {}
func testHandler92(foo int)  {}
func testHandler93(foo int)  {}
func testHandler94(foo int)  {}
func testHandler95(foo int)  {}
func testHandler96(foo int)  {}
func testHandler97(foo int)  {}
func testHandler98(foo int)  {}
func testHandler99(foo int)  {}
func testHandler100(foo int) {}
