from sklearn import svm
import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
from matplotlib import colors
from sklearn.model_selection import train_test_split


def show_accuracy(y_hat, y_test, param):
    pass


path = 'F:\\ssl\\first\\output\\data.txt'  # 样本数据文件路径
data = np.loadtxt(path, dtype=float)
test = np.loadtxt("F:\\ssl\\first\\output\\result_data.txt", dtype=float)  # 待检测数据

y, x = np.split(data, (1,), axis=1)

x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=0, train_size=0.999, test_size=0.001, stratify = y_all)
clf = svm.SVC(C=1, kernel='rbf', gamma=10, decision_function_shape='ovr')
clf.fit(x_train, y_train.ravel())

print(clf.score(x_train, y_train))  # 精度
y_hat = clf.predict(x_train)
print(clf.score(x_test, y_test))

result_hat = clf.predict(test)
result_ip = open("F:\\ssl\\first\\output\\result_ip.txt", "r")
result_file = open("F:\\ssl\\first\\output\\result.txt", "w")
for i in result_hat:
    line = result_ip.readline().strip()
    if i == -1:
        line += "white\n"
    else:
        line += "black\n"
    result_file.write(line)
result_file.close()
result_ip.close()
