import matplotlib.pyplot as plt
import numpy as np
from sklearn import tree
from sklearn.model_selection import train_test_split


def ave(list):
    a = 0
    if len(list) == 0:
        return 0
    for i in list:
        a += i
    return a / len(list)

# 画图函数
def draw(length, score, txt="param"):
    plt.plot(range(1, length + 1), score, color="red", label=txt)
    plt.legend()
    plt.show()

# 调参数画图用
def param_test(max, x, y):
    score = [i for i in range(max)]
    x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=None, train_size=0.5, test_size=0.5)
    for i in range(max):
        clf = tree.DecisionTreeClassifier(criterion="entropy"
                                          , random_state=30
                                          , splitter="best"
                                          , max_depth=i + 1 # 需要调的参数
                                          )
        clf.fit(x_train, y_train)
        score[i] = clf.score(x_test, y_test)
    draw(max, score)


path = 'F:\\ssl\\first\\output\\data.txt'  # 样本数据文件路径
data = np.loadtxt(path, dtype=float)
test = np.loadtxt("F:\\ssl\\first\\output\\result_data.txt", dtype=float)  # 待检测数据

clf = tree.DecisionTreeClassifier(criterion="entropy"
                                  , random_state=30
                                  , splitter="best"
                                  , max_depth = 16
                                  )
y, x = np.split(data, (1,), axis=1)
clf.fit(x, y)

#param_test(30, x, y)

result_hat = clf.predict(test)
result_ip = open("F:\\ssl\\first\\output\\result_ip.txt", "r")
result_file = open("F:\\ssl\\first\\output\\result3.txt", "w")
for i in result_hat:
    line = result_ip.readline().strip()
    if i == -1:
        line += "white\n"
    else:
        line += "black\n"
    result_file.write(line)
result_file.close()
result_ip.close()
