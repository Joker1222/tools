package tools

import (
	"fmt"
	"log"
	"time"
)

/*func main(){
	//全组合 C4,2
	r,err:=Comb([]int{11, 12, 13, 14},2)
	if err!=nil{
		log.Fatal(err)
	}
	log.Println("comb result:", r)
	log.Println("--------------------------------------")
	//全排列A4,2
	r,err=Perm([]int{11, 12, 13, 14},2)
	if err!=nil{
		log.Fatal(err)
	}
	log.Println("perm result:",r)
}*/
func Comb2(nums []int64) ([][]int64, error) {
	rst := make([][]int64, 0)
	l := int64(len(nums))
	var i int64
	var j int64
	for i = 0; i < l; i++ {
		for j = i + 1; j < l; j++ {
			rst = append(rst, []int64{i, j})
		}
	}
	return rst, nil
}
func Comb(nums []int64, m int64) ([][]int64, error) {
	timeStart := time.Now()
	n := int64(len(nums))
	indexs := zuheResult(n, m)
	result := findNumsByIndexs(nums, indexs)
	timeEnd := time.Now()
	log.Println("time consume:", timeEnd.Sub(timeStart))
	//结果是否正确
	rightCount := mathZuhe(n, m)
	if rightCount == int64(len(result)) {
		log.Println("result correct!")
		return result, nil
	} else {
		return nil, fmt.Errorf("结果错误，正确结果是：", rightCount)
	}
}

//组合算法(从nums中取出m个数)
func zuheResult(n int64, m int64) [][]int64 {
	if m < 1 || m > n {
		fmt.Println("Illegal argument. Param m must between 1 and len(nums).")
		return [][]int64{}
	}
	//保存最终结果的数组，总数直接通过数学公式计算
	result := make([][]int64, 0, mathZuhe(n, m))
	//保存每一个组合的索引的数组，1表示选中，0表示未选中
	indexs := make([]int64, n)
	var i int64
	for i = 0; i < n; i++ {
		if i < m {
			indexs[i] = 1
		} else {
			indexs[i] = 0
		}
	}
	//第一个结果
	result = addTo(result, indexs)

	for {
		find := false
		//每次循环将第一次出现的 1 0 改为 0 1，同时将左侧的1移动到最左侧
		var i int64
		for i = 0; i < n-1; i++ {
			if indexs[i] == 1 && indexs[i+1] == 0 {
				find = true
				indexs[i], indexs[i+1] = 0, 1
				if i > 1 {
					moveOneToLeft(indexs[:i])
				}
				result = addTo(result, indexs)
				break
			}
		}
		//本次循环没有找到 1 0 ，说明已经取到了最后一种情况
		if !find {
			break
		}
	}
	return result
}

//将ele复制后添加到arr中，返回新的数组
func addTo(arr [][]int64, ele []int64) [][]int64 {
	newEle := make([]int64, len(ele))
	copy(newEle, ele)
	arr = append(arr, newEle)
	return arr
}
func moveOneToLeft(leftNums []int64) {
	//计算有几个1
	sum := 0
	for i := 0; i < len(leftNums); i++ {
		if leftNums[i] == 1 {
			sum++
		}
	}
	//将前sum个改为1，之后的改为0
	for i := 0; i < len(leftNums); i++ {
		if i < sum {
			leftNums[i] = 1
		} else {
			leftNums[i] = 0
		}
	}
}

//根据索引号数组得到元素数组
func findNumsByIndexs(nums []int64, indexs [][]int64) [][]int64 {
	if len(indexs) == 0 {
		return [][]int64{}
	}
	result := make([][]int64, len(indexs))
	for i, v := range indexs {
		line := make([]int64, 0)
		for j, v2 := range v {
			if v2 == 1 {
				line = append(line, nums[j])
			}
		}
		result[i] = line
	}
	return result
}

//数学方法计算排列数(从n中取m个数)
func mathPailie(n int64, m int64) int64 {
	return jieCheng(n) / jieCheng(n-m)
}

//数学方法计算组合数(从n中取m个数)
func mathZuhe(n int64, m int64) int64 {
	return jieCheng(n) / (jieCheng(n-m) * jieCheng(m))
}

//阶乘
func jieCheng(n int64) int64 {
	var result int64 = 1
	var i int64
	for i = 2; i <= n; i++ {
		result *= i
	}
	return result
}

//全排列
func Perm(nums []int64, m int64) ([][]int64, error) {
	//组合结果
	zuhe, err := Comb(nums, m)
	if err != nil {
		return nil, err
	}
	//保存最终排列结果
	result := make([][]int64, 0)
	//遍历组合结果，对每一项进行全排列
	for _, v := range zuhe {
		p := quanPailie(v)
		result = append(result, p...)
	}
	return result, nil
}

//n个数全排列
//如输入[1 2 3]，则返回[123 132 213 231 312 321]
func quanPailie(nums []int64) [][]int64 {
	COUNT := len(nums)
	//检查
	if COUNT == 0 || COUNT > 10 {
		panic("Illegal argument. nums size must between 1 and 9.")
	}
	//如果只有一个数，则直接返回
	if COUNT == 1 {
		return [][]int64{nums}
	}
	//否则，将最后一个数插入到前面的排列数中的所有位置
	return insertItem(quanPailie(nums[:COUNT-1]), nums[COUNT-1])
}
func insertItem(res [][]int64, insertNum int64) [][]int64 {
	//保存结果的slice
	result := make([][]int64, len(res)*(len(res[0])+1))
	index := 0
	for _, v := range res {
		var i int64
		for i = 0; i < int64(len(v)); i++ {
			//在v的每一个元素前面插入新元素
			result[index] = insertToSlice(v, i, insertNum)
			index++
		}
		//在v最后面插入新元素
		result[index] = append(v, insertNum)
		index++
	}
	return result
}

//将元素value插入到数组nums中索引为index的位置
func insertToSlice(nums []int64, index int64, value int64) []int64 {
	result := make([]int64, len(nums)+1)
	copy(result[:index], nums[:index])
	result[index] = value
	copy(result[index+1:], nums[index:])
	return result
}
