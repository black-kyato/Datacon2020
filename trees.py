from sklearn.ensemble import RandomForestClassifier
import csv
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
import numpy as np

def ave(list):
    a = 0
    if len(list) == 0:
        return 0
    for i in list:
        a += i
    return a / len(list)


# 多组交叉验证
def multiScore(clf,  x, y, max = 2000):
    score = [i for i in range(max)]
    x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=None, train_size=0.6, test_size=0.4)
    for i in range(max):
        clf.fit(x_train, y_train.ravel())
        score[i] = clf.score(x_test, y_test)
    print(ave(score))


data=[]
traffic_feature=[]
traffic_target=[]

path = 'D:\\ssl\\first\\output\\data.txt'  # 样本数据文件路径
data = np.loadtxt(path, dtype=float)
traffic_target, traffic_feature = np.split(data, (1,), axis=1)

scaler = StandardScaler() # 标准化转换
scaler.fit(traffic_feature)  # 训练标准化对象
traffic_feature= scaler.transform(traffic_feature)   # 转换数据集
feature_train, feature_test, target_train, target_test = train_test_split(traffic_feature, traffic_target, random_state=None, train_size=0.6, test_size=0.4)
clf = RandomForestClassifier()
clf.fit(traffic_feature,traffic_target.ravel())
#print(clf.score(feature_test, target_test))

test = np.loadtxt("D:\\ssl\\first\\output\\result_data.txt", dtype=float)

scaler = StandardScaler() # 标准化转换
scaler.fit(test)  # 训练标准化对象
test= scaler.transform(test)   # 转换数据集
result_hat = clf.predict(test)
result_ip = open("D:\\ssl\\first\\output\\result_ip.txt", "r")
result_file = open("D:\\ssl\\first\\output\\result_trees.txt", "w")
for i in result_hat:
    line = result_ip.readline().strip()
    if i == 0:
        line += "white\n"
    else:
        line += "black\n"
    result_file.write(line)
result_file.close()
result_ip.close()